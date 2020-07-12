# WLLDriver
Created this driver to make request to WeatherLinkLive module including archive from Weatherlink.com when data be lost on Weewx.

Configuration : 

- Install the driver by using wee_extension --install WLLDriver.zip. You can download my repo as a ZIP or use this link : https://github.com/Drealine/WLLDriver/releases/download/0.2/WLLDriver.zip
- Change on weewx.conf station_type = WLLDriver
- Know your station ID by following this link : https://weatherlink.github.io/v2-api/authentication
default API request is : https://api.weatherlink.com/v2/stations?api-key=YOURAPIKEY&api-signature=YOURAPISIGNATURE&t=CURRENTTIMESTAMP
- Set parameters as you want at the end of weewx.conf: 

```
[WLLDriver]
    max_tries - #Max tries before Weewx raise an exception and finished the loop. Default : 10
    retry_wait - #Time to retry in second between each. Default : 5
    poll_interval - #The time to sleep in second between 2 requests. If you have enabled UDP please note that all sensor would be reach each poll_interval. Default : 10
    udp_enable - #Start broadcast each 3 secondes for Wind and Rain. 0 if you want to disable, 1 if you want to enable. Default : 0
    hostname - #Set your IP or hostname of WLL module.
    time_out - #Set this for timeout in second of HTTP and UDP request. Default : 10
    device_id - #Set the ID of your ISS that you've configured on the WLL Module. Ex : 1:iss-10:extraTemp1. Default : 1:iss. Be carefull for extra sensor because the column would be exist in Weewx database
    wl_apikey - #Create an API Key on your Weatherlink account
    wl_apisecret - #By creating API Key, you've also need an API Secret
    wl_stationid - #Check your station ID by using the method explain before
    wl_archive_interval - #Be carefull by set this because it depending on your subscription on Weatherlink.com. For better use, please set the same archive interval than the Weewx engine.
```

Credits : 

Thank to @vinceskahan on Github who give me examples to make this driver : 
https://github.com/vinceskahan/weewx-weatherlinklive-json

Thank to @grebleem to work on the developpment for the WLL Module : 
https://github.com/grebleem/weewx-weatherlinkliveudp

