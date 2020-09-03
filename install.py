from setup import ExtensionInstaller


def loader():
    return WLLDriverInstaller()


class WLLDriverInstaller(ExtensionInstaller):
    def __init__(self):
        super(WLLDriverInstaller, self).__init__(
            version='0.4',
            name='WLLDriver',
            description='Request data to WLL and lost data from Weatherlink.com',
            author="Drealine",
            config={
                'WLLDriver': {
                    'driver': 'user.WLLDriver',
                    'max_tries': 10,
                    'retry_wait': 5,
                    'poll_interval': 10,
                    'realtime_enable': 0,
                    'hostname': 'change_me',
                    'time_out': 10,
                    'device_id': 'iss:1',
                    'wl_archive_enable': 0,
                },
                'Accumulator': {
                    'rainRate': {
                        'extractor': 'max'
                    }
                },
            },

            files=[('bin/user', ['bin/user/WLLDriver.py'])]

        )