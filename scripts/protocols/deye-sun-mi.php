<?php
# Adapter for micro inverters of the Deye-SUNXXXX family.
# This adapter is working with all Deye micro inverters from SUN300G3 up to SUN2000G3 and similar OEM-inverters 
# (Bosswerk MI300, MI600, TurboEnergy etc.)
# You can monitor more than one inverter in a grid using multiple instances of this adapter.
#
# Author: soe135, based on the initial scripts from dr-ni/soe135 for Bosswerk MI600
# License GPL-v3+
#
# Please provide the <logger-/wifi serial number> of your micro inverter (a 10 digit number starting with 
# 41????????) in Admin -> Inverter(s) configuration -> field 'Communication options'. This parameter is 
# mandatory.
# example: lsn=4112345678
#
# This adapter requires an additional program (deye-logger) which is running outside of 123solar. This program 
# (deye-logger) queries all needed information from the Deye inverter via MODBUS-requests and provide this 
# information via UDP datagrams to this script.
# If the deye-logger program is running on the same machine like the web-server of 123solar there is no need to 
# provide additional parameters to this script. If you use an other host for running program deye-logger you have
# to specify the IP address of this machine in field 'Admin -> Inverter(s) configuration -> Communication options'.
# example: lsn=4112345678,server=192.168.1.200
# If you want to use another port (default is 48890) for the communication between program deye-logger and 
# this script you have to specify this port in field 'Admin -> Inverter(s) configuration -> Communication options'
# of 123solar and you have to run the program deye-logger with the command line option -p 12345.
# example: lsn=4112345678,server=192.168.1.200,port=48875
# All parameters in field 'Communication options' are separated by commas.
#
# The source code of program 'deye-logger' wich is needed to query the inverter data for this script is available at 
# folder '/123solar/misc/tools/deye-logger'. Please see the readme file in the mentioned folder.

if (!defined('checkaccess')) {die('Direct access not permitted');}

// -----------------------------------
// --- declaration of helper functions
// -----------------------------------

if (! function_exists('DeyeSunMi_ModBusCrc'))
{
  // This script is loaded/executed multiple times by 123solar. This hack prevents 
  // the fatal error 'Cannot redeclare <function>' in this case.
  function DeyeSunMi_ModBusCrc($data)
  {
    $crc = 0xFFFF;
    for ($pos = 0; $pos < strlen($data); $pos++) {
      $crc ^= (ord($data[$pos]) & 0xFF);
      for ($i = 8; $i != 0; $i--) { 
        // loop over each bit
        if (($crc & 0x0001) != 0) { 
          // if the LSB is set
          $crc >>= 1;                   // shift right and XOR 0xA001
          $crc ^= 0xA001;
        }
        else                            // else LSB is not set
          $crc >>= 1;                   // just shift right
      }
    }
    // string conversion and transformation into little endian format
    return sprintf("%04X", (($crc & 0xFF) << 8) + (($crc >> 8) & 0xFF));
  }
}

if (! function_exists('DeyeSunMi_GetParameter'))
{
  function DeyeSunMi_GetParameter($token, $parBuf)
  {
    $token = strtoupper($token);
    $parArray = explode(",", $parBuf);
    foreach($parArray as $index => $dataline) {
      $data = explode('=', $dataline);
      if (trim(strtoupper($data[0])) == $token) {
        return trim($data[1]);
      }
    }  
    return NULL;
  }
}

if (! function_exists('DeyeSunMi_QueryInverterData'))
{
  function DeyeSunMi_QueryInverterData($loggerSerial, $serverIP, $serverPort)
  {
    if (!($sock = socket_create(AF_INET, SOCK_DGRAM, getprotobyname('udp')))) {
      return NULL;
    }
    // set receive timeout to 2 seconds
    socket_set_option($sock, SOL_SOCKET, SO_RCVTIMEO, array("sec"=>2,"usec"=>0));
    // send our query to the server
    $command = "QueryInverterData[".$loggerSerial."]";
    if (! socket_sendto($sock, $command, strlen($command), 0, $serverIP, $serverPort)) {
      socket_close($sock);  
      return NULL;
    }
    $bytesReceived = socket_recv($sock, $reply, 1500, MSG_WAITALL);
    socket_close($sock);  
    if ($bytesReceived <= 5) {
      // response is to short to contain all needed data
      return NULL;
    }
    // We got an response from the server and the length is big enough to contain at least one data byte
    // plus delimiter and 4 byte checksum. Now we have to verify the checksum and if valid return the
    // received data
    $posCs = strpos($reply, "|");
    if (($posCs === false) || ($posCs != strlen($reply) - 5)) {
      // checksum delimiter not found or has wrong position
      return NULL;
    }
    $data = substr($reply, 0, $posCs);
    $checkSum = substr($reply, $posCs + 1, 4);
    if ($checkSum != DeyeSunMi_ModBusCrc($data)) {
      // checksum in response is not valid
      return NULL;
    }
    
    return $data;
  }
}

// -------------------
// --- begin of script
// -------------------

$CMD_RETURN = ''; // always initialize
$MATCHES = '';
$ERR = "0";
$SDTE = date("Ymd H:i:s");
$LOGFILE = "$INVTDIR/errors/deye-sun-mi.log";
$LAST_KWHTOTAL_FILE = "$INVTDIR/errors/lastKWHtotal.dat";
// read com-options
$LoggerSerial = DeyeSunMi_GetParameter("lsn", ${'COMOPTION'.$invt_num});
if (empty($LoggerSerial)) {
  $LoggerSerial = "undefined!";
}
$ServerIP = DeyeSunMi_GetParameter("server", ${'COMOPTION'.$invt_num});
if (empty($ServerIP)) {
  $ServerIP = "127.0.0.1";
}
$ServerPort = DeyeSunMi_GetParameter("port", ${'COMOPTION'.$invt_num});
if (empty($ServerPort)) {
  $ServerPort = 48890;
}
// string (array) data
$I1V = null;
$I1A = null;
$I1P = null;
$I2V = null;
$I2A = null;
$I2P = null;
$I3V = null;
$I3A = null;
$I3P = null;
$I4V = null;
$I4A = null;
$I4P = null;
// inverter data
$FRQ = null;
$EFF = null;
$INVT = null;
$BOOT = null;
$KWHT = null;
// grids, for Deye micro inverters only the first grid is used
$G1V = null;
$G1A = null;
$G1P = null;
$G2V = null;
$G2A = null;
$G2P = null;
$G3V = null;
$G3A = null;
$G3P = null;
// variable names to store process values for the specific inverter
$PREFIX = 'DEYE_SUN_MIINVT'; 
$LastPTS = $PREFIX.$invt_num.'_LASTPTS';
$LastKWHT = $PREFIX.$invt_num.'_LASTKWHT';
// other needed variables
$P = (float) 0;
$Dt = 0;
$MinSecondsBetweenMeasurements = 10;
$Now = time();
$KWHTDifference = (float) 0; // difference between the calculated KWHT-value and the (real) KWHT-value stored inside the inverter
$KWHTCorrectionFactor = (float) 0; // standard behaviour, no correction needed

// initializing process variables
if (!isset($$LastPTS)) $$LastPTS = $Now - $MinSecondsBetweenMeasurements; // last determination time for the power value of this inverter
if (!isset($$LastKWHT)) {
  $$LastKWHT = (float) 0;  // last KWH-total value of this inverter
  // In case LastKWHT is not properly set (i.e. after an 123solar restart) we try to load the stored value from disk.
  $StoredTotalKWH = (float) exec("cat ".$LAST_KWHTOTAL_FILE);
  if ($StoredTotalKWH > $$LastKWHT) {
    $$LastKWHT = $StoredTotalKWH;
  }
}

// the first measurement should be taken immediately, the following ones at the earliest after $MinSecondsBetweenMeasurements seconds
$SecondsElapsed = ($Now - $$LastPTS);
if ($SecondsElapsed < $MinSecondsBetweenMeasurements) {
  // we have to wait at least n sconds
  sleep($MinSecondsBetweenMeasurements - $SecondsElapsed);
}

$InverterData = DeyeSunMi_QueryInverterData($LoggerSerial, $ServerIP, $ServerPort);
if (substr($InverterData, 0, 15) == "LSN=".$LoggerSerial.";") {
  // we got valid data for the inverter from the server
  $IvDataA = explode(";", $InverterData);
  // extract all needed values
  foreach($IvDataA as $index => $dataline) {
    $dataline = trim($dataline);
    if (! empty($dataline)) {
      $data = explode('=', $dataline);
      $data[0] = trim($data[0]);
      if (! empty($data[1])) {
        $data[1] = trim($data[1]);
        switch ($data[0]) {
          case "DCVPV1":
            // DCVoltagePV1
            $I1V = (float) $data[1];
            break;
          case "DCVPV2":
            // DCVoltagePV2
            $I2V = (float) $data[1];
            break;
          case "DCVPV3":
            // DCVoltagePV3
            $I3V = (float) $data[1];
            break;
          case "DCVPV4":
            // DCVoltagePV4
            $I4V = (float) $data[1];
            break;
          case "DCCPV1":
            // DCCurrentPV1
            $I1A = (float) $data[1];
            break;
          case "DCCPV2":
            // DCCurrentPV2
            $I2A = (float) $data[1];
            break;
          case "DCCPV3":
            // DCCurrentPV3
            $I3A = (float) $data[1];
            break;
          case "DCCPV4":
            // DCCurrentPV4
            $I4A = (float) $data[1];
            break;
          case "DCPPV1":
            // DCPowerPV1
            $I1P = (float) $data[1];
            break;
          case "DCPPV2":
            // DCPowerPV2
            $I2P = (float) $data[1];
            break;
          case "DCPPV3":
            // DCPowerPV3
            $I3P = (float) $data[1];
            break;
          case "DCPPV4":
            // DCPowerPV4
            $I4P = (float) $data[1];
            break;
          case "TACOPA":
            // TotalACOutPowerActive
            $P = (float) $data[1];
            break;
          case "TPA":
            // TotalProductionActive
            $KWHTInverter = (float) $data[1];
            break;
          case "ACV1":
            // ACVoltage1
            $G1V = (float) $data[1];
            break;
          case "ACOF":
            // ACOutputFrequency
            $FRQ = (float) $data[1];
            break;
          case "ACRT":
            // ACRadiatorTemp
            $INVT = (float) $data[1];
            $BOOT = $INVT; // temperature dc/dc booster
            break;
        }
      }
    }
  }

  $Now = time();
  $Dt = $Now - $$LastPTS;
  $$LastPTS = $Now;

  if ($$LastKWHT == 0) {
    // the value is probably not set at this time
    if ($KWHTInverter > 0) {
       $$LastKWHT = $KWHTInverter;
    }  
    // check if our own calculated KWHT-value is greater then the value we read from the inverter
    // in this case we use our own stored value to avoid jumping KWHT backwards due to the missing decimal places 
    // of the value from the inverter
    $StoredTotalKWH = (float) exec("cat ".$LAST_KWHTOTAL_FILE);
    if ($StoredTotalKWH > $$LastKWHT) {
      $$LastKWHT = $StoredTotalKWH;
    }
  }

  // After a few days of production we face the problem that our calculated KWHT-value shows a positive drift 
  // compared to the (real) stored KWHT-value in the inverter. This problem results from rounding problems by
  // the smaller number of decimal places of the value KWHT in the inverter. To solve this problem 
  // we need a correction factor wich allows us a slightly reduce of our calculated KWHT-value over a longer 
  // time range. So should the calculated KWHT-value gradually approach the real value stored in the inverter 
  // over this longer time range. 
  if ($$LastKWHT - $KWHTInverter > 0.1) {
    // The positive drift is greater than 0.1, we should calculate a correction factor later.
    $KWHTDifference = $$LastKWHT - $KWHTInverter;
  }

  if ($Dt && $P) {
    // total-KWHT value of this inverter has to be updated. 
    $NewKWHTDelta = $P * $Dt * ((1.0 / (60.0 * 60.0)) / 1000.0);
    if ($KWHTDifference > 0.1) {
      // The positive drift of KWHT is greater than 0.1, we shold calculate an correction factor.
      // Normally we have an average of 5 measurements per minute --> 300 per hour --> 3600 for twelve hours.
      // The goal should be that the drift is eliminated within a day. So we use 3600 as base for our correction 
      // target, nearly a day of solar-operation. On the other hand we don't want to see an intense sawtooth graph so 
      // we limit the correction factor to a maximum of 10 percent of $NewKWHTDelta. 
      $KWHTCorrectionTarget = $KWHTDifference / 3600.0;
      $KWHTCorrectionFactor = $NewKWHTDelta / 10.0;
      if ($KWHTCorrectionFactor > $KWHTCorrectionTarget) {
        // the correction factor does not need to be so high, so we limit it
        $KWHTCorrectionFactor = $KWHTCorrectionTarget;
      }
    }
    $$LastKWHT += ($NewKWHTDelta - $KWHTCorrectionFactor);
    // save the value in case we stop 123solar and restart it again later. 
    file_put_contents("$LAST_KWHTOTAL_FILE", $$LastKWHT);    
  } 
} else {
  $ERR = "Can't get valid data for inverter '$LoggerSerial' from server '$ServerIP'!";
  $$LastPTS = time();
}

if ($DEBUG) {
  if ($ERR != "0") {
    file_put_contents("$LOGFILE", $SDTE.": $ERR\n", FILE_APPEND);
  } else {
    if ($KWHTCorrectionFactor > 0) {
      file_put_contents("$LOGFILE", $SDTE.": Ongoing KWHT-correction, KWHTDifference=".$KWHTDifference." KWHTCorrectionFactor=".$KWHTCorrectionFactor."\n", FILE_APPEND);
    }
    file_put_contents("$LOGFILE", $SDTE.": P=".$P." KWHTotal=".$$LastKWHT." NewKWHTDelta=".$NewKWHTDelta."\n", FILE_APPEND);
  }
}  

if (!isset($INVT)) $INVT = 0; // temperature inverter fixed dummy
if (!isset($BOOT)) $BOOT = 0; // temperature dc/dc booster fixed dummy

$G1P = (float) $P; // P-AC
if (($G1P > 0) && ($G1V > 0)) {
  $G1A = (float) round($G1P / $G1V, 2);
  $EFF = 96.5; // fixed value for efficiency based on the Deye datasheet
} else {
  $G1V= (float) 0;
  $G1A = (float) 0;
  $EFF = (float) 0; 
}
$KWHT = $$LastKWHT; 

if ($ERR == "0") {
  $RET = 'OK';
} else {
  $RET = 'NOK';
}

?>
