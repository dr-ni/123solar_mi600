/******************************************************************************
 * program:      deye-logger.c - server program to query Deye SUN family      *
 *               inverters in connection with 123solar.                       *
 *               This source is released under the GNU GPLv3 license          *
 *               (General Public License).                                    *
 *                                                                            *
 * author:       soe135                                                       *
 * created:      27.12.2022                                                   *
 * last mod.:    28.01.2023                                                   *
 ******************************************************************************/

//------------------------------------------------------------------------------
// needed includes
//------------------------------------------------------------------------------

//-- file includes
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
//-- object includes
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <cmath>
#include <iterator>
#include <sstream>

using namespace std;

//------------------------------------------------------------------------------
//--- constants
//------------------------------------------------------------------------------

//
// program constants
//
#define MAX_LOGGER_ENTRYS 5
// You should not reduce the LOGGER_QUERY_INTERVAL significantly. If you query the logger
// too often it leads to transmission problems from the logger side.
#define LOGGER_QUERY_INTERVAL 120 
// max data validity is 7 query cycles
#define LOGGER_DATA_VALID_INTERVAL (7 * LOGGER_QUERY_INTERVAL) 
#define MS_DELAY_AFTER_SEND_REQUEST 1000
#define SEC_SOCKET_TIMEOUT 5
#define LOGGER_DEF_PORT_NUMBER 48899
#define SERVER_DEF_PORT_NUMBER 48890
#define WIFIKIT_ID "WIFIKIT-214028-READ"
#define LOGGER_HOST_IP_LENGTH 15
#define LOGGER_SERIAL_NUMBER_LENGTH 10
#define LOGGER_MAC_ADDR_LENGTH 12
#define INVERTER_SERIAL_NUMBER_LENGTH 10
#define QUERY_TOKEN "QueryInverterData"
//
// other defines
//
#define ROUND_2_INT(f) ((int)(f >= 0.0 ? (f + 0.5) : (f - 0.5)))
//
// log defines
//
#define esyslog(a...) void( (SysLogLevel > 0) ? syslog(LOG_ERR,   a) : void() )
#define isyslog(a...) void( (SysLogLevel > 1) ? syslog(LOG_INFO,  a) : void() )
#define dsyslog(a...) void( (SysLogLevel > 2) ? syslog(LOG_DEBUG, a) : void() )

#define LOG_ERROR         esyslog("ERROR (%s,%d): %m", __FILE__, __LINE__)
#define LOG_ERROR_STR(s)  esyslog("ERROR: %s: %m", s)

//------------------------------------------------------------------------------
//--- type definitions
//------------------------------------------------------------------------------

typedef struct
{
  time_t DataTimeStamp;
  char LoggerHostIp[LOGGER_HOST_IP_LENGTH + 1];
  uint16_t LoggerPort;
  char LoggerSerialNumber[LOGGER_SERIAL_NUMBER_LENGTH + 1];
  char LoggerMacAddress[LOGGER_MAC_ADDR_LENGTH + 1];
  char InverterSerialNumber[INVERTER_SERIAL_NUMBER_LENGTH + 1];
  float InverterRatedPower;
  float DCVoltagePV1;
  float DCCurrentPV1;
  float DCPowerPV1;
  float DCVoltagePV2;
  float DCCurrentPV2;
  float DCPowerPV2;
  float DCVoltagePV3;
  float DCCurrentPV3;
  float DCPowerPV3;
  float DCVoltagePV4;
  float DCCurrentPV4;
  float DCPowerPV4;
  float DailyProductionPV1;
  float DailyProductionPV2;
  float DailyProductionPV3;
  float DailyProductionPV4;
  float DailyProductionActive;
  float TotalProductionPV1;
  float TotalProductionPV2;
  float TotalProductionPV3;
  float TotalProductionPV4;
  float TotalProductionActive;
  float TotalACOutPowerActive;
  float ACVoltage1;
  float ACCurrent1;
  float ACOutputFrequency;
  float ACRadiatorTemp;
  int NumberOfMPPTs;
  int NumberOfPhases;
} tInverterData;

typedef struct
{
  char LoggerIp[LOGGER_HOST_IP_LENGTH + 1];
  uint16_t LoggerPort;
  char LoggerSerialNumber[LOGGER_SERIAL_NUMBER_LENGTH + 1];
  time_t LastQueryDt;
  time_t LastValidDataDt;
  bool InverterDataValid;
  tInverterData InverterData;
} tLoggerEntry;

//------------------------------------------------------------------------------
// --- needed global variables
//------------------------------------------------------------------------------

static char progname[50] = "uninitialized";
static int SysLogLevel = 3;
volatile sig_atomic_t ShouldBeTerminated = 0;
static int TerminatedBy = 0;

//------------------------------------------------------------------------------
//--- helper functions
//------------------------------------------------------------------------------

// Wait for some number of milliseconds
void delay(unsigned int howLong)
{
  struct timespec sleeper, dummy;
  sleeper.tv_sec = (time_t)(howLong / 1000);
  sleeper.tv_nsec = (long)(howLong % 1000) * 1000000;
  nanosleep(&sleeper, &dummy);
}

static void SignalHandler(int signum)
{
  if (signum != SIGPIPE)
  {
    TerminatedBy = signum;
    ShouldBeTerminated = 1;
  }
  signal(signum, SignalHandler);
}

void OpenLog(const char* argv_0)
{
  // get our own program name
  const char* p = (const char*) strrchr(argv_0, '/');
  p = p ? (p + 1) : argv_0;
  strncpy(progname, p, sizeof(progname));
  *(progname + sizeof(progname) - 1) = '\0';
  openlog(progname, LOG_PID | LOG_CONS, LOG_USER);
}

bool MakeDirs(const char *FileName, bool IsDirectory)
{
  bool result = true;
  char *s = strdup(FileName);
  char *p = s;
  if (*p == '/') p++;
  while ((p = strchr(p, '/')) != NULL || IsDirectory)
  {
    if (p) *p = 0;
    struct stat fs;
    if ((stat(s, &fs) != 0) || ! S_ISDIR(fs.st_mode))
    {
      dsyslog("creating directory %s", s);
      if (mkdir(s, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) == -1)
      {
        LOG_ERROR_STR(s);
        result = false;
        break;
      }
    }

    if (p) *p++ = '/'; else break;
  }
  free(s);

  return result;
}

// trim from start (in place)
static inline void ltrim(std::string& s) 
{
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
}

// trim from end (in place)
static inline void rtrim(std::string& s) 
{
  s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string& s) 
{
  rtrim(s);
  ltrim(s);
}

bool IsLoggerAlive(const char* host)
{
  // check if inverters web-server is alive --> connection to logger possible?
  // sometimes the web-server is not answering to the first request so we try it multipe times
  if (! host) return false;
  int socketFd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (socketFd < 0)
  {
    return false;
  }
  sockaddr_in sockAddr;
  memset((char*) &sockAddr, 0, sizeof(sockAddr));
  sockAddr.sin_family = AF_INET;
  sockAddr.sin_port = htons(80);
  sockAddr.sin_addr.s_addr = inet_addr(host);
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  setsockopt(socketFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  int retryCount = 3;
  int resConnect = -1;
  while ((retryCount-- > 0) && (resConnect < 0))
  {
    resConnect = ::connect(socketFd, (struct sockaddr*) &sockAddr, sizeof(sockAddr));
    if ((resConnect < 0) && (retryCount > 0)) delay(500);
  }  
  close(socketFd);
  
  return (resConnect < 0) ? false : true;
}

unsigned int GetModBusCrc(const unsigned char* buf, int count)  
{  
  unsigned int crc = 0xFFFF;
  if (buf)
  {
    for (int pos = 0; pos < count; pos++)
    {
      crc ^= (unsigned int)buf[pos];    // XOR byte into least sig. byte of crc

      for (int i = 8; i != 0; i--) 
      {    
        // loop over each bit
        if ((crc & 0x0001) != 0) 
        {      
          // if the LSB is set
          crc >>= 1;                    // shift right and XOR 0xA001
          crc ^= 0xA001;
        }
        else                            // else LSB is not set
          crc >>= 1;                    // just shift right
      }
    }
  }
  
  // put it in the little endian format
    return (((crc & 0xFF) << 8) | ((crc & 0xFF00) >> 8));
}

//------------------------------------------------------------------------------
//--- cInverterCommunication
//------------------------------------------------------------------------------

class cInverterCommunication
{
  public:
    // returncodes for method queryData
    enum eQueryDataRetCode { qdrcOK = 0, qdrcConnectError = 1, qdrcOtherError = 2 };
  
  public:
    cInverterCommunication(const char* hostname, uint16_t port);
    ~cInverterCommunication(void);
    eQueryDataRetCode queryData(tInverterData* inverterdata);

    inline void GetCommLog(string& commlog)
    {
      commlog.assign(commLog.c_str());
    }

    inline void GetErrorText(string& errortext)
    {
      errortext.assign(errorText.c_str());
    }
    
  private:
    enum eCommType { ctSend = 1, ctReceive = 2};

  private:
    int DecodeHexChar(char nibble);
    bool AppendModBusCrc(string& hexString);
    bool CheckModBusCrc(string& hexString);
    bool SendData(string& message, int& errNo);
    bool ReadResponse(string& response, int& errNo);
    bool ReadModBusData(int startReg, int wordCount, string& data, int& errNo, string& eText);
    void WriteToCommLog(eCommType commType, const char* logMessage, int byteCount);
    void PutErrMsg(const char* errDesc, int errNo);
    float GetModBusFloatValue(string& modBusData, size_t startPos, bool isDoubleWord, unsigned int divider);
    void ExtractModBusData(tInverterData* inverterdata); 
  
  private:
    string hostName;
    uint16_t Port;
    int socketFd;
    sockaddr_in sockAddr;
    size_t sockAddrSize;
    string commLog;
    string errorText;
    string modBusDataBlockOne;
    string modBusDataBlockTwo;
    string modBusDataBlockThree;
    string modBusDataBlockFour;
    string modBusDataBlockFive;
};

cInverterCommunication::cInverterCommunication(
  const char* hostname,
  uint16_t port)
{
  if (hostname) hostName.assign(hostname);
  Port = (port == 0 ? LOGGER_DEF_PORT_NUMBER : port) ;
  socketFd = 0;  
}  

cInverterCommunication::~cInverterCommunication(void)
{
  if (socketFd)
  {
    ::close(socketFd); 
    socketFd = 0;
  }  
}  

cInverterCommunication::eQueryDataRetCode cInverterCommunication::queryData(
  tInverterData* inverterdata)
{
  // this method return 
  //   qdrcOK - everything went O.K. and the inverter data could be read
  //   qdrcConnectError - in case connect to inverter was not possible
  //   qdrcOtherError - in case of all other errors (communication, checksum etc.) 
  // data in *inverterdata are only valid if method returned qdrcOK!
  if (! inverterdata)
  {
    errorText = "Pointer to data structure 'inverterdata' is null";
    return qdrcOtherError;
  }
  // initialize data structures
  memset((char*) inverterdata, 0, sizeof(tInverterData));
  if (socketFd)
  {
    ::close(socketFd); 
    socketFd = 0;
  }  
  commLog = "";
  errorText = "";
  socketFd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (socketFd < 0)
  {
    string dummy = "Can't create socket for ";
    dummy.append(hostName.c_str());
    PutErrMsg(dummy.c_str(), errno);
    socketFd = 0;
    return qdrcOtherError;
  }
  memset((char*) &sockAddr, 0, sizeof(sockAddr));
  sockAddr.sin_family = AF_INET;
  sockAddr.sin_port = htons(Port);
  sockAddr.sin_addr.s_addr = inet_addr(hostName.c_str());
  struct timeval tv;
  tv.tv_sec = SEC_SOCKET_TIMEOUT;
  tv.tv_usec = 0;
  setsockopt(socketFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  sockAddrSize = sizeof(sockAddr);
  // try to connect to inverter
  char timeBuf[50];
  time_t now = time(NULL);
  struct tm tmVal = *localtime(&now);
  strftime(timeBuf, sizeof(timeBuf), "%F %T", &tmVal);
  std::cout << std::endl << timeBuf << std::endl << "Connecting to "<< hostName << ":" << Port << "..." << std::endl;
  string msg = WIFIKIT_ID;
  string response;
  string dummyStr;
  int errNo;
  if (! SendData(msg, errNo))
  {
    dummyStr = "Can't connect to " + hostName;
    PutErrMsg(dummyStr.c_str(), errNo);
    ::close(socketFd); 
    socketFd = 0;
    return qdrcConnectError;
  }
  if (! ReadResponse(response, errNo))
  {
    dummyStr = "Can't get requested connect response from " + hostName;
    PutErrMsg(dummyStr.c_str(), errNo);
    ::close(socketFd); 
    socketFd = 0;
    return qdrcConnectError;
  }
  // check response, the first parameter is the LoggerIp, the second is the LoggerMacAddress and the 
  // third one is the LoggerSerialNumber
  if (response.empty())
  {
    dummyStr = "Got empty connect response from " + hostName;
    PutErrMsg(dummyStr.c_str(), 0);
    ::close(socketFd); 
    socketFd = 0;
    return qdrcConnectError;
  }
  int commaCount = std::count(response.begin(), response.end(), ',');
  int posFirstComma = response.find(",");
  int posLastComma = response.rfind(",");
  if ((commaCount != 2) || (posFirstComma < 7) || (posFirstComma > LOGGER_HOST_IP_LENGTH))
  {
    dummyStr = "Unable to find LoggerHostIpAddress in connect response from " + hostName;
    PutErrMsg(dummyStr.c_str(), 0);
    ::close(socketFd); 
    socketFd = 0;
    return qdrcConnectError;
  }  
  strncpy(inverterdata->LoggerHostIp, response.substr(0, posFirstComma).c_str(), LOGGER_HOST_IP_LENGTH + 1);
  inverterdata->LoggerHostIp[LOGGER_HOST_IP_LENGTH] = 0;
  inverterdata->LoggerPort = Port;
  if ((commaCount != 2) || (posLastComma - posFirstComma != LOGGER_MAC_ADDR_LENGTH + 1))
  {
    dummyStr = "Unable to find LoggerMacAddress in connect response from " + hostName;
    PutErrMsg(dummyStr.c_str(), 0);
    ::close(socketFd); 
    socketFd = 0;
    return qdrcConnectError;
  }  
  strncpy(inverterdata->LoggerMacAddress, response.substr(posFirstComma + 1, LOGGER_MAC_ADDR_LENGTH).c_str(), LOGGER_MAC_ADDR_LENGTH + 1);
  inverterdata->LoggerMacAddress[LOGGER_MAC_ADDR_LENGTH] = 0;
  if ((commaCount != 2) || (((int) response.length()) != posLastComma + LOGGER_SERIAL_NUMBER_LENGTH + 1))
  {
    dummyStr = "Unable to find LoggerSerialNumber in connect response from " + hostName;
    PutErrMsg(dummyStr.c_str(), 0);
    ::close(socketFd); 
    socketFd = 0;
    return qdrcConnectError;
  }  
  strncpy(inverterdata->LoggerSerialNumber, response.substr(posLastComma + 1).c_str(), LOGGER_SERIAL_NUMBER_LENGTH + 1);
  inverterdata->LoggerSerialNumber[LOGGER_SERIAL_NUMBER_LENGTH] = 0;
  msg = "+ok";
  if (! SendData(msg, errNo))
  {
    dummyStr = "Unable to send 'connect accepted' to " + hostName;
    PutErrMsg(dummyStr.c_str(), errNo);
    ::close(socketFd); 
    socketFd = 0;
    return qdrcConnectError;
  }
  // connect to inverter is done, query first block of MODBUS data
  std::cout << "Reading data block one..." << std::endl;
  if (! ReadModBusData(0x0003, 5, modBusDataBlockOne, errNo, dummyStr))
  {
    dummyStr = "Unable to read first MODBUS-data block from " + hostName + "(" + dummyStr + ")";
    PutErrMsg(dummyStr.c_str(), errNo);
    ::close(socketFd); 
    socketFd = 0;
    return qdrcOtherError;
  }
  // query second block of MODBUS data
  std::cout << "Reading data block two..." << std::endl;
  if (! ReadModBusData(0x0010, 3, modBusDataBlockTwo, errNo, dummyStr))
  {
    dummyStr = "Unable to read second MODBUS-data block from " + hostName + "(" + dummyStr + ")";
    PutErrMsg(dummyStr.c_str(), errNo);
    ::close(socketFd); 
    socketFd = 0;
    return qdrcOtherError;
  }
  // query third block of MODBUS data
  std::cout << "Reading data block three..." << std::endl;
  if (! ReadModBusData(0x006D, 8, modBusDataBlockThree, errNo, dummyStr))
  {
    dummyStr = "Unable to read third MODBUS-data block from " + hostName + "(" + dummyStr + ")";
    PutErrMsg(dummyStr.c_str(), errNo);
    ::close(socketFd); 
    socketFd = 0;
    return qdrcOtherError;
  }
  // query fourth block of MODBUS data
  std::cout << "Reading data block four..." << std::endl;
  if (! ReadModBusData(0x003C, 20, modBusDataBlockFour, errNo, dummyStr))
  {
    dummyStr = "Unable to read fourth MODBUS-data block from " + hostName + "(" + dummyStr + ")";
    PutErrMsg(dummyStr.c_str(), errNo);
    ::close(socketFd); 
    socketFd = 0;
    return qdrcOtherError;
  }
  // query fifth block of MODBUS data
  std::cout << "Reading data block five..." << std::endl;
  if (! ReadModBusData(0x0056, 5, modBusDataBlockFive, errNo, dummyStr))
  {
    dummyStr = "Unable to read fifth MODBUS-data block from " + hostName + "(" + dummyStr + ")";
    PutErrMsg(dummyStr.c_str(), errNo);
    ::close(socketFd); 
    socketFd = 0;
    return qdrcOtherError;
  }
  // all needed data read, disconnect
  std::cout << "Disconnecting from "<< hostName << ":" << Port << "..." << std::endl;
  msg = "AT+Q\n";
  if (! SendData(msg, errNo))
  {
    dummyStr = "Unable to disconnect from  ";
    dummyStr.append(hostName.c_str());
    PutErrMsg(dummyStr.c_str(), errNo);
    ::close(socketFd); 
    socketFd = 0;
    return qdrcOtherError;
  }
  ::close(socketFd); 
  socketFd = 0;
  // extracting MODBUS data into inverterdata structure
  ExtractModBusData(inverterdata);
  
  return qdrcOK;
}  

int cInverterCommunication::DecodeHexChar(
  char nibble)
{
  // this function return -1 if the given char has a non hex-value otherwise the
  // corresponding decimal value is returned
  nibble = toupper(nibble);
  if ((nibble >= '0') && (nibble <= '9'))
  {
    return nibble - '0'; 
  }
  if ((nibble >= 'A') && (nibble <= 'F'))
  {
    return (nibble - 'A') + 10; 
  }
   
  return -1; 
}

bool cInverterCommunication::AppendModBusCrc(
  string& hexString)
{
  int length = hexString.length();
  if (length && ((length & 0x01) == 0))
  {
    // the hex-string contains data and has an even length
    size_t bufSize = (length >> 1);
    unsigned char* buf = new unsigned char[bufSize];
    if (! buf) return false;
    // split string into buffer
    int i = 0;
    unsigned char* bufPtr = buf;
    while (i < length)
    {
      int UpperNibble = DecodeHexChar(hexString[i++]);
      int LowerNibble = DecodeHexChar(hexString[i++]);
      if ((LowerNibble >= 0) && (UpperNibble >= 0))
      {
        // the data format of this byte is O.K.
        *bufPtr++ = (UpperNibble << 4) | LowerNibble;
      }
      else
      {
        // invalid hex string
        delete buf;
        return false;
      }
    }
    // get MODBUS-CRC
    char crc[10];
    sprintf(crc, "%04X", GetModBusCrc(buf, bufSize));
    delete buf;
    hexString.append(crc);

    return true;
  }
  
  return false;
}

bool cInverterCommunication::CheckModBusCrc(
  string& hexString)
{
  int length = hexString.length();
  if ((length >= 6) && ((length & 0x01) == 0))
  {
    // the hex-string contains at least one data byte, plus two byte CRC-sum and has an even length
    size_t bufSize = ((length - 4) >> 1);
    unsigned char* buf = new unsigned char[bufSize];
    if (! buf) return false;
    // split string into buffer
    int i = 0;
    unsigned char* bufPtr = buf;
    while (i < length - 4)
    {
      int UpperNibble = DecodeHexChar(hexString[i++]);
      int LowerNibble = DecodeHexChar(hexString[i++]);
      if ((LowerNibble >= 0) && (UpperNibble >=0))
      {
        // the data format of this byte is O.K.
        *bufPtr++ = (UpperNibble << 4) | LowerNibble;
      }
      else
      {
        // invalid hex string
        delete buf;
        return false;
      }
    }
    // get MODBUS-CRC
    char crc[10];
    sprintf(crc, "%04X", GetModBusCrc(buf, bufSize));
    delete buf;
    if (strcmp(crc, hexString.substr(length - 4).c_str()) == 0)
    {
      // calculated CRC is equal to the CRC stored at the end of the hex string
      return true;
    }  
  }
  
  return false;
}

bool cInverterCommunication::SendData(
  string& message, 
  int& errNo)
{
  int n_bytes = ::sendto(socketFd, message.c_str(), message.length(), 0, (sockaddr*) &sockAddr, sockAddrSize);
  errNo = errno;
  WriteToCommLog(ctSend, message.c_str(), n_bytes);
  if (n_bytes < 0) return false;
  delay(MS_DELAY_AFTER_SEND_REQUEST);
  
  return true;
}
  
bool cInverterCommunication::ReadResponse(
  string& response, 
  int& errNo)
{
  response = "";
  int responseBufSize = 1500;
  char* responseBuf = new char[responseBufSize];
  if (! responseBuf)
  {
    errNo = ENOMEM;
    return false;
  }
  socklen_t saSize = sizeof(sockaddr_in);
  int n_bytes = ::recvfrom(socketFd, responseBuf, responseBufSize, 0, (sockaddr*) &sockAddr, &saSize);
  if (n_bytes < 0)
  {
    errNo = errno;
    delete responseBuf;
    return false;
  }
  *(responseBuf + n_bytes) = 0;
  response.assign(responseBuf);
  delete responseBuf;
  // remove special character 0x10 from response
  response.erase(std::remove_if(response.begin(), response.end(), [](char &c) { return (c == 0x10); }), response.end());  
  // remove leading and trailing spaces
  trim(response); 
  WriteToCommLog(ctReceive, response.c_str(), response.length());
  errNo = 0;
  
  return true;
}  

bool cInverterCommunication::ReadModBusData(
  int startReg, 
  int wordCount, 
  string& data, 
  int& errNo, 
  string& eText)
{
  data = "";
  eText = "";
  errNo = 0;
  if (! wordCount)
  {
    errNo = EINVAL;
    eText = "value of parameter wordCount invalid!";
    return false;
  }
  // build the query command
  char buf[50];
  // slave-Id + function + startReg + wordCount 
  sprintf(buf, "%s%04X%04X", "0103", startReg, wordCount);
  string request(buf);
  AppendModBusCrc(request);
  request = "AT+INVDATA=8," + request + "\n";
  if (! SendData(request, errNo))
  {
    eText = "error during send MODBUS-request";
    return false;
  }
  
  string response; 
  if (! ReadResponse(response, errNo))
  {
    eText = "error during the reception of the MODBUS-response";
    return false;
  }
  
  // check the answer we got
  size_t expectedLength = 4; // strlen of "+ok="
  expectedLength += 6;  // strlen of "0103??" --> ?? is the wordcount of the payload
  expectedLength += wordCount * 4;  // 4 hex-char per requested register-word
  expectedLength += 4;  // strlen of "????" --> MODBUS-checksum
  if ((response.find("+ok=") != 0) || (response.length() != expectedLength))
  {
    eText = "answer of MODBUS-request is malformed";
    return false;
  }
  // delete token "+ok="
  response.erase(0, 4);
  if (! CheckModBusCrc(response))
  {
    eText = "invalid checksum of MODBUS answer";
    return false;
  }
  
  // received data seem to be O.K.
  data.assign(response.c_str());
  
  return true;
}  

void cInverterCommunication::WriteToCommLog(
  eCommType commType,
  const char* logMessage,
  int byteCount)
{
  if (logMessage)
  {
    time_t timeVal = time(NULL);
    struct tm tmVal = *localtime(&timeVal);
    char logBuf[100];
    strcpy(logBuf, "--> ");
    strftime(strchr(logBuf, 0), sizeof(logBuf) - 50, "%F %T", &tmVal);
    strcat(logBuf, ", ");
    sprintf(strchr(logBuf, 0), "%d", byteCount);
    strcat(logBuf, (commType == ctSend) ? " bytes sent:" : " bytes received:");
    strcat(logBuf, "\n> ");
    commLog.append(logBuf);
    commLog.append(logMessage);
    if ((! commLog.empty()) && (commLog.back() != '\n'))
    {
      commLog.append("\n");
    }
  }
}  

void cInverterCommunication::PutErrMsg(
  const char* errDesc, 
  int errNo)
{
  if (errDesc)
  {
    errorText = errDesc;
    if (errNo)
    {
      char errBuf[50];
      sprintf(errBuf, ": errno=%d, ", errNo);
      errorText.append(errBuf);
      char* p = strerror(errNo); 
      errorText.append((p != NULL) ? p : "UNKNOWN ERROR");
    }
  }
} 

float cInverterCommunication::GetModBusFloatValue(
  string& modBusData,
  size_t startPos,
  bool isDoubleWord, 
  unsigned int divider)
{
  string HexString;
  if (isDoubleWord)
  {
    HexString = modBusData.substr(startPos + 4, 4);
  }  
  HexString += modBusData.substr(startPos, 4);
  std::transform(HexString.begin(), HexString.end(), HexString.begin(), ::toupper);
  int DummyInt;
  sscanf(HexString.c_str(), "%X", &DummyInt);
  
  if (divider <= 1)
  {
    return float(DummyInt);
  }

  return float(DummyInt) / float(divider);
}

void cInverterCommunication::ExtractModBusData(
  tInverterData* inverterdata)
{
  // this method does not perform any further data checking, since the validity of the received
  // data (length, checksum, etc.) has already been checked by the calling method.
  //
  inverterdata->DataTimeStamp = time(NULL);
  // extract data block one
  for (int i = 0; i < INVERTER_SERIAL_NUMBER_LENGTH; i++)
  {
    inverterdata->InverterSerialNumber[i] = modBusDataBlockOne[7 + (i * 2)];
  }
  inverterdata->InverterSerialNumber[INVERTER_SERIAL_NUMBER_LENGTH] = 0;
  // extract data block two
  inverterdata->InverterRatedPower = GetModBusFloatValue(modBusDataBlockTwo, 6, true, 10); 
  inverterdata->NumberOfMPPTs = atoi(modBusDataBlockTwo.substr(14, 2).c_str());
  inverterdata->NumberOfPhases = atoi(modBusDataBlockTwo.substr(16, 2).c_str());
  // extract data block three
  inverterdata->DCVoltagePV1 = GetModBusFloatValue(modBusDataBlockThree, 6, false, 10);
  inverterdata->DCCurrentPV1 = GetModBusFloatValue(modBusDataBlockThree, 10, false, 10);
  inverterdata->DCPowerPV1 = inverterdata->DCVoltagePV1 * inverterdata->DCCurrentPV1;
  inverterdata->DCVoltagePV2 = GetModBusFloatValue(modBusDataBlockThree, 14, false, 10);
  inverterdata->DCCurrentPV2 = GetModBusFloatValue(modBusDataBlockThree, 18, false, 10);
  inverterdata->DCPowerPV2 = inverterdata->DCVoltagePV2 * inverterdata->DCCurrentPV2;
  inverterdata->DCVoltagePV3 = GetModBusFloatValue(modBusDataBlockThree, 22, false, 10);
  inverterdata->DCCurrentPV3 = GetModBusFloatValue(modBusDataBlockThree, 26, false, 10);
  inverterdata->DCPowerPV3 = inverterdata->DCVoltagePV3 * inverterdata->DCCurrentPV3;
  inverterdata->DCVoltagePV4 = GetModBusFloatValue(modBusDataBlockThree, 30, false, 10);
  inverterdata->DCCurrentPV4 = GetModBusFloatValue(modBusDataBlockThree, 34, false, 10);
  inverterdata->DCPowerPV4 = inverterdata->DCVoltagePV4 * inverterdata->DCCurrentPV4;
  // extract data block four
  inverterdata->DailyProductionActive = GetModBusFloatValue(modBusDataBlockFour, 6, false, 10);
  inverterdata->TotalProductionActive = GetModBusFloatValue(modBusDataBlockFour, 18, true, 10);
  inverterdata->DailyProductionPV1 = GetModBusFloatValue(modBusDataBlockFour, 26, false, 10);
  inverterdata->DailyProductionPV2 = GetModBusFloatValue(modBusDataBlockFour, 30, false, 10);
  inverterdata->DailyProductionPV3 = GetModBusFloatValue(modBusDataBlockFour, 34, false, 10);
  inverterdata->DailyProductionPV4 = GetModBusFloatValue(modBusDataBlockFour, 38, false, 10);
  inverterdata->TotalProductionPV1 = GetModBusFloatValue(modBusDataBlockFour, 42, false, 10);
  inverterdata->TotalProductionPV2 = GetModBusFloatValue(modBusDataBlockFour, 50, false, 10);
  inverterdata->ACVoltage1 = GetModBusFloatValue(modBusDataBlockFour, 58, false, 10);
  inverterdata->TotalProductionPV3 = GetModBusFloatValue(modBusDataBlockFour, 62, false, 10);
  inverterdata->ACCurrent1 = GetModBusFloatValue(modBusDataBlockFour, 70, false, 10);
  inverterdata->TotalProductionPV4 = GetModBusFloatValue(modBusDataBlockFour, 74, false, 10);
  inverterdata->ACOutputFrequency = GetModBusFloatValue(modBusDataBlockFour, 82, false, 100);
  // extract data block five
  inverterdata->TotalACOutPowerActive = GetModBusFloatValue(modBusDataBlockFive, 6, true, 10);
  inverterdata->ACRadiatorTemp = (GetModBusFloatValue(modBusDataBlockFive, 22, false, 100)) - 10.0;
  if ((inverterdata->TotalACOutPowerActive <= 0) && (inverterdata->ACRadiatorTemp == -10.0)) 
  {
    // special case: the inverter (logger) is alive but there is not enough energy to power up
    // the AC-converter and to provide the current temperature of the AC-converter
    // --> set the temperature to 0
    inverterdata->ACRadiatorTemp = 0;
  }
} 

//------------------------------------------------------------------------------
//--- cProgData
//------------------------------------------------------------------------------

class cProgData
{
  public:
    cProgData(void);
    ~cProgData(void);
    inline int GetLoggerEntryCount()
    {
      return LoggerEntryCount;
    }
    bool AddLoggerEntry(const char* loggerIp, uint16_t loggerPort);
    tLoggerEntry* GetLoggerEntry(int index);
    inline bool GetDisplayInverterData(void)
    {
      return DisplayInverterData;
    }
    inline void SetDisplayInverterData(bool value)
    {
      DisplayInverterData = value;
    }
    inline bool GetDisplayModBusCommunication(void)
    {
      return DisplayModBusCommunication;
    }
    inline void SetDisplayModBusCommunication(bool value)
    {
      DisplayModBusCommunication = value;
    }
    inline bool GetDisplayServerCommunication(void)
    {
      return DisplayServerCommunication;
    }
    inline void SetDisplayServerCommunication(bool value)
    {
      DisplayServerCommunication = value;
    }
    inline const char* GetDataFileDir(void)
    {
      return DataFileDir.c_str();
    }
    inline void SetDataFileDir(const char* value)
    {
      DataFileDir.assign(value);
    }
    inline uint16_t GetServerPort(void)
    {
      return ServerPort;
    }
    inline void SetServerPort(uint16_t value)
    {
      ServerPort = (value == 0) ? SERVER_DEF_PORT_NUMBER : value;
    }
    void GetStatusFileName(const char* loggerIp, string& statusFileName);
    void EncodeInverterData(const char* loggerSerial, string& data);
    inline void Lock(void)
    {
      pthread_mutex_lock(&DataMutex);
    }
    inline void UnLock(void)
    {
      pthread_mutex_unlock(&DataMutex);
    }

  private:
    int LoggerEntryCount;
    tLoggerEntry LoggerEntrys[MAX_LOGGER_ENTRYS];
    bool DisplayInverterData;
    bool DisplayModBusCommunication; 
    bool DisplayServerCommunication; 
    string DataFileDir;
    uint16_t ServerPort;
    pthread_mutex_t DataMutex;
};

cProgData::cProgData(void)
{
  LoggerEntryCount = 0;
  memset(&LoggerEntrys, 0, sizeof(LoggerEntrys));
  DisplayInverterData = false;
  DisplayModBusCommunication = false;
  DisplayServerCommunication = false;
  ServerPort = SERVER_DEF_PORT_NUMBER;
  pthread_mutex_init(&DataMutex, NULL);
}

cProgData::~cProgData(void)
{
  // remove all logger-statusfiles
  for (int i = 0; i < LoggerEntryCount; i++)
  {
    string statusFileName;
    GetStatusFileName(LoggerEntrys[i].LoggerIp, statusFileName);
    if (! statusFileName.empty())
    {
      ::remove(statusFileName.c_str());
    }
  }
  // release mutex
  pthread_mutex_destroy(&DataMutex);
}

bool cProgData::AddLoggerEntry(
  const char* loggerIp, 
  uint16_t loggerPort)
{
  if ((LoggerEntryCount < MAX_LOGGER_ENTRYS) && loggerIp)
  {
    // check if there is already an entry for the given IP
    for (int i = 0; i < LoggerEntryCount; i++)
    {
      if (strcmp(LoggerEntrys[i].LoggerIp, loggerIp) == 0)
      {
        // entry is already existing
        return false;
      }
    }
    tLoggerEntry* e = &(LoggerEntrys[LoggerEntryCount]);
    strncpy(e->LoggerIp, loggerIp, LOGGER_HOST_IP_LENGTH + 1);
    e->LoggerIp[LOGGER_HOST_IP_LENGTH] = 0;
    e->LoggerPort = loggerPort;
    // all other members are already cleared by the constructor of cProgData
    LoggerEntryCount++;
    
    return true;
  }
  
  return false;
}
  
tLoggerEntry* cProgData::GetLoggerEntry(
  int index)
{
  if ((index < 0) || (index >= LoggerEntryCount))
  {
    return 0;
  }
  
  return &(LoggerEntrys[index]);
}  

void cProgData::GetStatusFileName(
  const char* loggerIp, 
  string& statusFileName)
{
  statusFileName = "";
  if (loggerIp)
  {
    statusFileName.assign(loggerIp);
    std::replace(statusFileName.begin(), statusFileName.end(), '.', '_');
    statusFileName.append(".status");
    statusFileName.insert(0, DataFileDir);
  }
}  

void cProgData::EncodeInverterData(
  const char* loggerSerial, 
  string& data)
{
  data = "";
  if (loggerSerial)
  {
    Lock();
    tInverterData* id = NULL;
    // searching for an entry with this loggerSerial and valid data
    for (int i = 0; i < LoggerEntryCount; i++)
    {
      if ((strcmp(LoggerEntrys[i].LoggerSerialNumber, loggerSerial) == 0) && (LoggerEntrys[i].InverterDataValid))
      {
        id = &(LoggerEntrys[i].InverterData);
      }
    }
    if (id)
    {
      char buf[200];
      sprintf(buf,"%s=%s;%s=%ld;%s=%s;%s=%d;%s=%s;",
        "LSN", id->LoggerSerialNumber,
        "DTS", id->DataTimeStamp,
        "LHI", id->LoggerHostIp,
        "LP", id->LoggerPort,
        "LMA", id->LoggerMacAddress);
      data.append(buf);  
      sprintf(buf,"%s=%s;%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;",
        "ISN", id->InverterSerialNumber,
        "IRP", id->InverterRatedPower,
        "DCVPV1", id->DCVoltagePV1,
        "DCCPV1", id->DCCurrentPV1,
        "DCPPV1", id->DCPowerPV1,
        "DCVPV2", id->DCVoltagePV2,
        "DCCPV2", id->DCCurrentPV2,
        "DCPPV2", id->DCPowerPV2);
      data.append(buf);  
      sprintf(buf,"%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;",
        "DCVPV3", id->DCVoltagePV3,
        "DCCPV3", id->DCCurrentPV3,
        "DCPPV3", id->DCPowerPV3,
        "DCVPV4", id->DCVoltagePV4,
        "DCCPV4", id->DCCurrentPV4,
        "DCPPV4", id->DCPowerPV4,
        "DPPV1", id->DailyProductionPV1,
        "DPPV2", id->DailyProductionPV2);
      data.append(buf);  
      sprintf(buf,"%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;",
        "DPPV3", id->DailyProductionPV3,
        "DPPV4", id->DailyProductionPV4,
        "DPA", id->DailyProductionActive,
        "TPPV1", id->TotalProductionPV1,
        "TPPV2", id->TotalProductionPV2,
        "TPPV3", id->TotalProductionPV3,
        "TPPV4", id->TotalProductionPV4,
        "TPA", id->TotalProductionActive);
      data.append(buf);  
      sprintf(buf,"%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;%s=%.1f;%s=%d;%s=%d;",
        "TACOPA", id->TotalACOutPowerActive,
        "ACV1", id->ACVoltage1,
        "ACC1", id->ACCurrent1,
        "ACOF", id->ACOutputFrequency,
        "ACRT", id->ACRadiatorTemp,
        "NOMPPT", id->NumberOfMPPTs,
        "NOP", id->NumberOfPhases);
      data.append(buf);  
    }
    UnLock();
  } 
}  

//------------------------------------------------------------------------------

void BuildInverterDataScreen(
  const tInverterData* id, 
  string& dataScreen)
{
  dataScreen = "";
  if (! id)
  {
    dataScreen = "No valid data structures given!";
    return;
  }
  char timeBuf[50];
  struct tm tmVal = *localtime(&id->DataTimeStamp);
  strftime(timeBuf, sizeof(timeBuf), "%F %T", &tmVal);
  char buf[200];
  sprintf(buf, "Data read from logger %s:%d\n\n",  id->LoggerHostIp, id->LoggerPort);
  dataScreen.append(buf);
  sprintf(buf, "+--------------------------------------+--------------------------------------+\n");
  dataScreen.append(buf);
  sprintf(buf, "| DCVoltagePV1          :  %7.1f V   | DCVoltagePV2         :   %7.1f V   |\n", id->DCVoltagePV1, id->DCVoltagePV2);
  dataScreen.append(buf);
  sprintf(buf, "| DCCurrentPV1          :  %7.1f A   | DCCurrentPV2         :   %7.1f A   |\n", id->DCCurrentPV1, id->DCCurrentPV2);
  dataScreen.append(buf);
  sprintf(buf, "| DCPowerPV1            :  %7.1f W   | DCPowerPV2           :   %7.1f W   |\n", id->DCPowerPV1, id->DCPowerPV2);
  dataScreen.append(buf);
  sprintf(buf, "| DailyProductionPV1    :  %7.1f kWh | DailyProductionPV2   :   %7.1f kWh |\n", id->DailyProductionPV1, id->DailyProductionPV2);
  dataScreen.append(buf);
  sprintf(buf, "| TotalProductionPV1    :  %7.1f kWh | TotalProductionPV2   :   %7.1f kWh |\n", id->TotalProductionPV1, id->TotalProductionPV2);
  dataScreen.append(buf);
  sprintf(buf, "+--------------------------------------+--------------------------------------+\n");
  dataScreen.append(buf);
  sprintf(buf, "| DCVoltagePV3          :  %7.1f V   | DCVoltagePV4         :   %7.1f V   |\n", id->DCVoltagePV3, id->DCVoltagePV4);
  dataScreen.append(buf);
  sprintf(buf, "| DCCurrentPV3          :  %7.1f A   | DCCurrentPV4         :   %7.1f A   |\n", id->DCCurrentPV3, id->DCCurrentPV4);
  dataScreen.append(buf);
  sprintf(buf, "| DCPowerPV3            :  %7.1f W   | DCPowerPV4           :   %7.1f W   |\n", id->DCPowerPV3, id->DCPowerPV4);
  dataScreen.append(buf);
  sprintf(buf, "| DailyProductionPV3    :  %7.1f kWh | DailyProductionPV4   :   %7.1f kWh |\n", id->DailyProductionPV3, id->DailyProductionPV4);
  dataScreen.append(buf);
  sprintf(buf, "| TotalProductionPV3    :  %7.1f kWh | TotalProductionPV4   :   %7.1f kWh |\n", id->TotalProductionPV3, id->TotalProductionPV4);
  dataScreen.append(buf);
  sprintf(buf, "+--------------------------------------+--------------------------------------+\n");
  dataScreen.append(buf);
  sprintf(buf, "| CurrentPower          :  %7.1f W   | InverterSerialNumber :    %s |\n", id->TotalACOutPowerActive, id->InverterSerialNumber);
  dataScreen.append(buf);
  sprintf(buf, "| YieldToday            :  %7.1f kWh | InverterRatedPower   :   %7.1f W   |\n", id->DailyProductionActive, id->InverterRatedPower);
  dataScreen.append(buf);
  sprintf(buf, "| TotalYield            :  %7.1f kWh | NumberOfMPPTs        :   %7d     |\n", id->TotalProductionActive, id->NumberOfMPPTs);
  dataScreen.append(buf);
  sprintf(buf, "| ACVoltage1            :  %7.1f V   | NumberOfPhases       :   %7d     |\n", id->ACVoltage1, id->NumberOfPhases);
  dataScreen.append(buf);
  sprintf(buf, "| ACCurrent1            :  %7.1f A   | LoggerSerialNumber   :    %s |\n", id->ACCurrent1, id->LoggerSerialNumber);
  dataScreen.append(buf);
  sprintf(buf, "| ACOutputFrequency     :  %7.1f Hz  | LoggerMacAddress     :  %s |\n", id->ACOutputFrequency, id->LoggerMacAddress);
  dataScreen.append(buf);
  sprintf(buf, "| ACRadiatorTemperature :  %7.1f GrdC| DataTimeStamp  : %s |\n", id->ACRadiatorTemp, timeBuf);
  dataScreen.append(buf);
  sprintf(buf, "+--------------------------------------+--------------------------------------+\n");
  dataScreen.append(buf);
}  

//------------------------------------------------------------------------------

static void *QueryingLoggers(void* ptr) 
{
  cProgData* progData = (cProgData*) ptr;
  int loggerNum = 0;
  while (! ShouldBeTerminated)
  {
    tLoggerEntry* LoggerEntry = progData->GetLoggerEntry(loggerNum);
    if (LoggerEntry)
    {
      time_t now = time(NULL);
      if (now >= LoggerEntry->LastQueryDt + LOGGER_QUERY_INTERVAL)
      {
        // it's time to query this logger
        cInverterCommunication IC(LoggerEntry->LoggerIp, LoggerEntry->LoggerPort);
        tInverterData* id = new tInverterData;
        cInverterCommunication::eQueryDataRetCode ret = IC.queryData(id);
        if (ret != cInverterCommunication::qdrcOK)
        {
          string errorText;
          IC.GetErrorText(errorText); 
          std::cout << "ReturnCode = " << ret << std::endl;
          std::cout << "ErrorText = " << errorText.c_str() << std::endl;
          if ((LoggerEntry->LastValidDataDt + LOGGER_DATA_VALID_INTERVAL < now) ||
              (! IsLoggerAlive(LoggerEntry->LoggerIp))) 
          {
            // too much time has passed since receiving the last valid data or
            // connection to the inverter is impossible
            progData->Lock();
            LoggerEntry->InverterDataValid = false;
            progData->UnLock();
            string statusFileName;
            progData->GetStatusFileName(LoggerEntry->LoggerIp, statusFileName);
            if (! statusFileName.empty())
            {
              char buf[50];
              string message = "No valid data received from logger ";
              sprintf(buf, "%s:%d", LoggerEntry->LoggerIp, LoggerEntry->LoggerPort);
              message.append(buf);
              message.append(" since\n'");
              struct tm tmVal = *localtime(&(LoggerEntry->LastValidDataDt));
              strftime(buf, sizeof(buf), "%F %T", &tmVal);
              message.append(buf);
              message.append("'.\n");
              ofstream statusFile;
              statusFile.open(statusFileName.c_str());
              statusFile << message;
              statusFile.close();
            } 
          }
        }
        else
        {
          // data are valid, transfer them to the internal memory
          // only the query thread do modify the internal data so we only have
          // to lock it here. The main program has to lock and unlock the data
          // on every access.
          progData->Lock();
          LoggerEntry->LastValidDataDt = now;
          LoggerEntry->InverterDataValid = true;
          memcpy(&(LoggerEntry->InverterData), id, sizeof(tInverterData));
          if ((! LoggerEntry->LoggerSerialNumber[0]) || 
              (strcmp(LoggerEntry->LoggerSerialNumber, "0000000000") == 0))
          {
            // logger serial number is not set, copy the serial from structure id
            strcpy(LoggerEntry->LoggerSerialNumber, id->LoggerSerialNumber);
          }
          progData->UnLock();
          // write status file
          string statusFileName;
          progData->GetStatusFileName(LoggerEntry->LoggerIp, statusFileName);
          if (! statusFileName.empty())
          {
            string dataScreen;
            BuildInverterDataScreen(&(LoggerEntry->InverterData), dataScreen);
            ofstream statusFile;
            statusFile.open(statusFileName.c_str());
            statusFile << dataScreen;
            statusFile.close();
          }
        }
        if (progData->GetDisplayModBusCommunication())
        {
          string commLog;
          IC.GetCommLog(commLog); 
          std::cout << "CommLog = \n" << commLog.c_str() << std::endl;
        }  
        if ((ret == cInverterCommunication::qdrcOK) && progData->GetDisplayInverterData())
        {
          string dataScreen;
          BuildInverterDataScreen(&(LoggerEntry->InverterData), dataScreen);
          std::cout << dataScreen << std::endl;
        }
        
        delete id;
        LoggerEntry->LastQueryDt = now;
      }
    }
    loggerNum = (loggerNum < progData->GetLoggerEntryCount() - 1) ? loggerNum + 1 : 0;
    // wait for 250ms
    delay(250);
  }  
  pthread_exit((void*) pthread_self());
}

//------------------------------------------------------------------------------

bool handleCommandLine(
  int argc, 
  char* argv[],
  cProgData* progData)
{
  // all occured error messages are displayed by this funtion
  if (! progData)
  {
    fprintf(stderr, "%s !!! Out of memory !!!\n", argv[0]);
    return false;
  }
  
  string errorText;
  string loggerIpList;
  string serverPort;
  int opt;
  while ((opt = getopt(argc, argv, "c:p:ims")) != -1) 
  {
    switch (opt) 
    {
      case 'c':
        loggerIpList.assign(optarg);
        trim(loggerIpList);
        break;
      case 'p':
        serverPort.assign(optarg);
        trim(serverPort);
        break;
      case 'i':
        progData->SetDisplayInverterData(true);
        break;
      case 'm':
        progData->SetDisplayModBusCommunication(true);
        break;
      case 's':
        progData->SetDisplayServerCommunication(true);
        break;
      case '?':
        errorText = "Unknown parameter";;
        break;
     }
  }  
  
  if (errorText.empty() && (! serverPort.empty()))
  {
    bool invalidPort = false;
    for (int i = 0; i < (int) serverPort.length(); i++)
    {
      if ((serverPort[i] < '0') || (serverPort[i] > '9'))
      {
        invalidPort = true;
        break;
      }
    }

    int serverPortNumber = atoi(serverPort.c_str());
    if ((serverPortNumber < 1) || (serverPortNumber > 65535) || invalidPort)
    {
      errorText = "Parameter serverPortNumber is invalid. Must be between 1 and 65535";
    }
    else
    {
      progData->SetServerPort((uint16_t) serverPortNumber);
    }
  }
  
  if (errorText.empty())
  {
    if (! loggerIpList.empty())
    {
      bool malformedIpList = true;
      string dummyStr = loggerIpList;
      // remove all allowed chars
      dummyStr.erase(std::remove_if(dummyStr.begin(), dummyStr.end(), [](char &c) { return (strchr("0123456789.,", c) != NULL); }), dummyStr.end());  
      // if IP-list is valid there should be no chars left
      if (dummyStr.empty())
      {
        // only valid chars are in the list, check format of the list
        if (std::count(loggerIpList.begin(), loggerIpList.end(), ',') < MAX_LOGGER_ENTRYS)
        {
          loggerIpList.append(",");
          malformedIpList = false;
          while ((! loggerIpList.empty()) && (! malformedIpList))
          {
            malformedIpList = true;
            size_t posFirstComma = loggerIpList.find(",");
            int a, b, c, d;
            int res = sscanf(loggerIpList.substr(0, posFirstComma).c_str(), "%d.%d.%d.%d", &a, &b, &c, &d);
            loggerIpList.erase(0, posFirstComma + 1);
            if ((res == 4) && (a >= 0) && (a <= 255) && (b >= 0) && (b <= 255) &&
                (c >= 0) && (c <= 255) && (d >= 0) && (d <= 255))
            {
              char ipAddr[LOGGER_HOST_IP_LENGTH + 1];
              sprintf(ipAddr, "%d.%d.%d.%d", a, b, c, d);
              if (progData->AddLoggerEntry(ipAddr, LOGGER_DEF_PORT_NUMBER))
              {           
                malformedIpList = false;
              }
              else
              {
                errorText = "Same IP is twice in loggerIpList"; 
              }  
            }
          }
        }
        else
        {
          errorText = "Too many entrys in loggerIpList"; 
        }
      }
      if (errorText.empty() && malformedIpList)
      {
        errorText = "Malformed parameter loggerIpList"; 
      }
    }
    else
    {
      errorText = "Missing parameter loggerIpList"; 
    }
  }
 
  if (! errorText.empty())
  {
    fprintf(stderr, 
      "\n!!! %s !!!\n\n"\
      "Usage: %s -c loggerIpList [-p serverPort] [-i] [-m]\n"\
      "  -c --> This parameter is mandatory. You must provide at least one loggerIp\n"\
      "         to monitor an inverter. If you like to monitor more than one\n"\
      "         inverter you can specify up to %d IP-addresses separated by\n"\
      "         a comma. (i.e. for two inverters: -c 192.168.1.1,192.168.1.2)\n"\
      "  -p --> This parameter is optional. Here you can provide an alternate port\n"\
      "         (1..65565) instead of the standard port %d used for the server\n"\
      "         communication with 123solar. Normally this parameter does not need\n"
      "         to be changed. If you use your own port please change the value\n"\
      "         also in the inverter communication options of 123solar!\n"\
      "  -i --> This parameter is optional. If specified, the data read from the\n"\
      "         inverter will be displayed on the screen.\n"\
      "  -m --> This parameter is optional. If specified, the data communication with\n"\
      "         the inverter via MODBUS will be displayed on the screen.\n"\
      "  -s --> This parameter is optional. If specified, the server communication\n"\
      "         with 123solar via network will be displayed on the screen.\n\n", 
      errorText.c_str(), argv[0], MAX_LOGGER_ENTRYS, SERVER_DEF_PORT_NUMBER);

    return false;
  }    
  
  return true;
}

//------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
  int _errno = 0;
  cProgData* progData = new cProgData();
  if (! handleCommandLine(argc, argv, progData))
  {
    // something went wrong during the initialization of the program
    // error messages were already displayed by the function
    if (progData) delete progData;
    exit(EXIT_FAILURE);
  }  

  // enable program-log
  OpenLog(argv[0]);

  const int bufferSize = 1500;
  char* buffer = new char[bufferSize]; 
  if (! buffer)
  {
    fprintf(stderr, "%s !!! Out of memory !!!\n", progname);
    esyslog("%s: !!! Out of memory !!!\n", progname);
    delete progData;
    exit(EXIT_FAILURE);
  }
  
  // set mask for file access
  // S_IRUSR | S_IWUSR | // owner
  // S_IRGRP | S_IWGRP | // group
  // S_IROTH | S_IWOTH   // others
  umask(0);

  // create our own temp data directory
  {
    string dfd = "/tmp/";
    dfd.append(progname);
    dfd.append("/");
    progData->SetDataFileDir(dfd.c_str());
    MakeDirs(dfd.c_str(), true);
  }  

  // set signal-handlers
  if (signal(SIGHUP, SignalHandler) == SIG_IGN) signal(SIGHUP, SIG_IGN);
  if (signal(SIGINT, SignalHandler) == SIG_IGN) signal(SIGINT, SIG_IGN);
  if (signal(SIGTERM, SignalHandler) == SIG_IGN) signal(SIGTERM, SIG_IGN);
  if (signal(SIGPIPE, SignalHandler) == SIG_IGN) signal(SIGPIPE, SIG_IGN);
  
  // start logger-query thread
  pthread_t LoggerQueryThread;
  if (pthread_create(&LoggerQueryThread, NULL, QueryingLoggers, (void*) progData) != 0)
  {
    _errno = errno;
    fprintf(stderr, "%s: Unable to create LoggerQueryThread: %s!\n", progname, strerror(_errno));
    esyslog("%s: Unable to create LoggerQueryThread: %s!\n", progname, strerror(_errno));
    delete buffer;
    delete progData;
    exit(EXIT_FAILURE);
  }
  
  size_t queryTokenLength = strlen(QUERY_TOKEN);
  struct sockaddr_in serveraddr;
  struct sockaddr_in clientaddr;
  socklen_t clientlen = sizeof(clientaddr);

  int sockfd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
  { 
    _errno = errno;
    fprintf(stderr, "%s: ERROR while opening the server socket: %s!\n", progname, strerror(_errno));
    esyslog("%s: ERROR while opening server the socket: %s!\n", progname, strerror(_errno));
    delete buffer;
    delete progData;
    exit(EXIT_FAILURE);
  }  

  // setsockopt: Handy debugging trick that lets 
  // us rerun the server immediately after we kill it; 
  // otherwise we have to wait about 20 secs. 
  // Eliminates "ERROR on binding: Address already in use" error. 
  int optval = 1;
  ::setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void*) &optval, sizeof(optval));

  // set timeout values for the socket
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  ::setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  ::setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  // init server addr structures
  memset(&serveraddr, 0, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
  serveraddr.sin_port = htons(progData->GetServerPort());

  // bind:  associate the parent socket with a port 
  if (::bind(sockfd, (struct sockaddr*) &serveraddr, sizeof(serveraddr)) < 0) 
  { 
    _errno = errno;
    close(sockfd);
    fprintf(stderr, "%s: ERROR while binding the server socket: %s!\n", progname, strerror(_errno));
    esyslog("%s: ERROR while binding server the socket: %s!\n", progname, strerror(_errno));
    delete buffer;
    delete progData;
    exit(EXIT_FAILURE);
  }  

  // main loop...
  while (! ShouldBeTerminated)
  {
    memset(buffer, 0, bufferSize);
    // receive an inverter query request from a client
    int n = recvfrom(sockfd, buffer, bufferSize, 0, (struct sockaddr*) &clientaddr, &clientlen);
    if (n < 0)
    {
      _errno = errno;
      if (_errno != EAGAIN)
      {
        // an real error has occured
        fprintf(stderr, "\n%s: ERROR on recvfrom: %s!\n", progname, strerror(_errno));
      }  
    }  
    if (n > 0)
    {  
      *(buffer + min(n + 1, (bufferSize - 1))) = 0;
      if (progData->GetDisplayServerCommunication())
      {
        // gethostbyaddr: determine who sent the datagram
        struct hostent* hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr, sizeof(clientaddr.sin_addr.s_addr), AF_INET);
        if (hostp == NULL)
        {
          _errno = errno;
          fprintf(stderr, "\n%s: ERROR on gethostbyaddr: %s!\n", progname, strerror(_errno));
        }  
        char* hostaddrp = inet_ntoa(clientaddr.sin_addr);
        if (hostaddrp == NULL)
        {
          _errno = errno;
          fprintf(stderr, "\n%s: ERROR on inet_ntoa: %s!\n", progname, strerror(_errno));
        }
        if (hostp && hostaddrp)
        {
          printf("server received datagram of %d bytes from %s (%s:%d):\n%s\n", 
            n, hostp->h_name, hostaddrp, ntohs(clientaddr.sin_port), buffer);
        }
      }  
      
      string data(buffer);
      // erase CR/LF from string
      data.erase(std::remove_if(data.begin(), data.end(), [](char &c) { return ((c == 0x0D) || (c == 0x0A)); }), data.end());  
      // erase leading and trailing spaces
      trim(data);
      // valid query request?
      if ((data.find(QUERY_TOKEN"[") == 0) && 
          (data.length() == LOGGER_SERIAL_NUMBER_LENGTH + queryTokenLength + 2) && 
          (data.back() == ']'))
      {
        string lsn = data.substr(queryTokenLength + 1, LOGGER_SERIAL_NUMBER_LENGTH);
        // required data locking is already done inside the following method
        progData->EncodeInverterData(lsn.c_str(), data);
        if (data.empty())
        {
          data = "There are no valid data for this inverter!";  
        }
        // append MODBUS CRC sum
        char crcBuf[10];
        sprintf(crcBuf, "|%04X", GetModBusCrc((const unsigned char*) data.c_str(), (int) data.length()));
        data.append(crcBuf);
        if (progData->GetDisplayServerCommunication())
        {
          std::cout << "Reply:" << std::endl << data << std::endl;
        }  
        // send requested data back to the client
        n = sendto(sockfd, data.c_str(), data.length(), 0, (struct sockaddr*) &clientaddr, clientlen);
        if (n < 0) 
        {
          _errno = errno;
          fprintf(stderr, "\n%s: ERROR on sendto: %s!\n", progname, strerror(_errno));
        }
      }  
    }

    delay(100);
  }

  close(sockfd);
  delete buffer;
  delete progData;
  dsyslog("%s terminated. Terminated by signal %d.", progname, TerminatedBy);

  exit(EXIT_SUCCESS);
}
