## ida-wakatime-py

### What is this?
[WakaTime](https://wakatime.com/) integration for [IDA Pro](https://hex-rays.com/)

### Installation:
0. Buy [IDA Pro](https://hex-rays.com/) (_optional_)
1. Register at [WakaTime](https://wakatime.com) and copy your [API Key](https://wakatime.com/settings/account)
2. Download this repo
3. Extract `wakatime.py` to the directory `$(IDA_PATH)/plugins`
4. Start IDA Pro
5. Enter your API Key
6. That's pretty much it.

### Tested on:
- [x] v9.0 beta
- [x] v8.3
- [x] v7.7 SP 3
- [x] v7.7 SP 1
- [x] v7.7
- [x] v7.5
- [x] v7.2

_Please help me in testing this plugin on other versions and open a pull request_

### Screenshot:
![img](https://i.imgur.com/tN1xsdm.png) \
![img2](https://i.imgur.com/1A3XgWG.png)

### Troubleshooting:
1. If by any chance on the first run ida doesn't ask you for your api key and **there are no errors in console**, that means that you've used wakatime plugins before and your apikey was already set in `~\.wakatime.cfg`

If you're reaching an unknown error you are free to open an issue.

### Contributing
Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Thanks to:
[wakatime/sublime-wakatime](https://github.com/wakatime/sublime-wakatime) - Pretty much everything related to `wakatime-cli`
