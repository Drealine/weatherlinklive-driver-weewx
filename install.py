from setup import ExtensionInstaller

def loader():
    return WLLDriverInstaller()

class WLLDriverInstaller(ExtensionInstaller):
    def __init__(self):
        super(WLLDriverInstaller, self).__init__(
            version='0.2',
            name='WLLDriver',
            description='Request data to WLL and lost data from Weatherlink.com',
            author="Drealine",
            config={
                'WLLDriver': {
                    'driver' : 'user.WLLDriver',
                    'max_tries' : 10,
                    'retry_wait' : 5,
                    'poll_interval' : 10,
                    'udp_enable' : 0,
                    'hostname' : 'change_me',
                    'time_out' : 10,
                    'device_id' : '1:iss',
                    'wl_apikey' : 'change_me',
                    'wl_apisecret' : 'change_me',
                    'wl_stationid' : 'change_me',
                    'wl_archive_interval' : 5,

                },
    
            },

            files=[('bin/user',['bin/user/WLLDriver.py'])]

        )