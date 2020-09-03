WLLDriver
============
Created this driver to make request to WeatherLinkLive module including archive from Weatherlink.com when data be lost on Weewx.

## Installation

- Download the latest release of WLLDriver : https://github.com/Drealine/weatherlinklive-driver-weewx/releases
- Install the driver : ```wee_extension --install WLLDriver.zip```
- Find on weewx.conf ```station_type``` and change by this : ```station_type = WLLDriver```

## Create your API Key v2

If you want to use weatherlink.com to retrieve lost data when Weewx crash, you have to create an API Key.

- Create your API Key v2 on https://www.weatherlink.com/account
- Use this tool to know your station ID : https://repl.it/repls/MeaslyExternalMegabyte#main.php by change ```api-key``` and ```api-secret``` and run the script.
- Keep in mind your station ID

## Set conf on Weewx

After installing driver, a new stanza appear at the end of the file weewx.conf.

### Default setting needed to run the driver

- ```max_tries``` - Max tries before Weewx raise an exception and finished the loop.<br />
- ```retry_wait``` - Time to retry in second between each.<br />
- ```poll_interval``` - The time to sleep in second between 2 requests. If you have enabled UDP please note that all sensor would be reach each poll_interval.<br />
- ```realtime_enable``` - Start broadcast each 3 secondes for Wind and Rain.<br />
- ```hostname``` - Set your IP or hostname of WLL module.<br />
- ```time_out``` - Set this for timeout in second of HTTP and UDP request.<br />
- ```device_id``` - Set the ID of your ISS that you've configured on the WLL Module. Ex : iss:1-extraTemp1:10. Default : iss:1.<br />

