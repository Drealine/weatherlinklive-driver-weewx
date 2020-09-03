WLLDriver
============
Created this driver to make request to WeatherLinkLive module including archive from Weatherlink.com when data be lost on Weewx.

## Installation

- Download the latest release of WLLDriver : https://github.com/Drealine/weatherlinklive-driver-weewx/releases
- Install the driver : ```wee_extension --install WLLDriver.zip```
- Find on **weewx.conf** ```station_type``` and change by this : ```station_type = WLLDriver```
- If you want to retrieve new data when the driver fail, set ```loop_on_init = True``` on **weewx.conf**

## Configuration on Weewx

After installing driver, a new stanza appear at the end of the file **weewx.conf**.

The correct syntax for set a parameter is : ```blabla = 1```

### Default setting needed to run the driver

- ```max_tries``` - Max tries before Weewx raise an exception and finished the loop.<br />
- ```retry_wait``` - Time to retry in second between each.<br />
- ```poll_interval``` - The time to sleep in second between 2 requests. If you have enabled UDP please note that all sensor would be reach each poll_interval.<br />
- ```realtime_enable``` - Enable realtime each 3 secondes for Wind and Rain.<br />
- ```hostname``` - Set your IP or hostname of WLL module.<br />
- ```time_out``` - Set this for timeout in second of HTTP and UDP request.<br />
- ```device_id``` - Set the ID of your ISS that you've configured on the WLL Module.<br />
- ```wl_archive_enable``` - Enable retrieve data from Weatherlink.com.<br />

### Retrieve data from Weatherlink.com

If you want to use weatherlink.com to retrieve lost data when Weewx crash for example, you have to create an API Key :

- Create your API Key v2 on https://www.weatherlink.com/account
- Use this tool to know your station ID : https://repl.it/repls/MeaslyExternalMegabyte#main.php by change ```api-key``` and ```api-secret``` and run the script.

Enable the feature ```wl_archive_enable = 1``` and set parameters on **weewx.conf** in [WLLDriver] :

- ```wl_apikey``` - Create an API Key on your Weatherlink account.
- ```wl_apisecret``` - By creating API Key, you've also need an API Secret.
- ```wl_stationid``` - Check your station ID by using the method explain before.
- ```wl_archive_interval``` - Be carefull by set this because it depending on your subscription on Weatherlink.com. For better use, please set the same archive interval than the Weewx engine.

### Add extra sensor or deported sensor

WLLDriver support at the moment only 5 extraTemp, 5 extraHumid or 1 Wind deported.

| Sensor        | Type |
| ------|-----|
| **iss** | Set the ISS |
| **extraTempX** | Set an extra temperature sensor with X is the number |
| **extraHumidX** | Set an extra humidity sensor with X is the number |

**/!\ ISS and ID must be set at first on parameter.**<br/>
**/!\ When adding sensors, make sur that schema is correct on Weewx. If not, please add a schema by following this tutorial : https://github.com/poblabs/weewx-belchertown/wiki/Adding-a-new-observation-type-to-the-WeeWX-database**

If you want to enable for example an extra temp sensor, set like this : ```device_id = iss:1-extraTemp1:2```<br/>
You can ajust and add more extra sensors like this : ```device_id = iss:1-extraTemp1:2-extraTemp2:4-extraHumid1:7```<br/>
Each parameter is separated by **```-```**

### Wind 2min

**/!\ Not supported if realtime is enabled.**

Weatherlink Live module can calculate wind average and gust each 2min instead of 10min by default. <br/>
To enable this, set this parameter on [WLLDriver] : ```wind_2min_enable = 1```

### Change HTTP port

You can change the default port 80 to set a new port to request to the WLL module. To change to 8080 for example, set this parameter on [WLLDriver] : ```port = 8080```

### Default value for each parameter

| Parameter        | Default value      | Min/Max |
| ------|-----|-----|
| **max_tries** | 10 | 0/200 |
| **retry_wait** | 5 | 0/NA	|
| **poll_interval** 	| 5 | 0/NA |
| **realtime_enable** | 0 | 0 = Disable / 1 = Enable |
| **time_out** | 10 | 0/15 |
| **wl_archive_enable** | 0 | 0 = Disable / 1 = Enable |
| **device_id** | iss:1 | NA |
| **wl_archive_interval** | NA | 1, 5 or 15 |
| **wind_2min_enable** | Not set so, 0 | 0 = Disable / 1 = Enable |
| **port** | 80 | NA |


