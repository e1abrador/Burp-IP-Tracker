![image](https://github.com/e1abrador/Burp-IP-Logger/assets/74373745/0850a68e-a3e3-450b-baca-3946ca3c87ec)

## TL;DR

### Installation

Go to the Extensions -> Installed -> Add -> iptracker.py

### Why?

Usually in a red team engagement it is needed to log all IP addresses used in the exercise. By using this extension, Burp will log all IP addresses used automatically, so the auditor can focus on testing and stop caring about what IP address he has used.

## Using

Once the extension is loaded, it will start logging your IP address:

![image](https://github.com/e1abrador/Burp-IP-Logger/assets/74373745/592eb967-d84c-4195-9b93-3f0f0adf5f8e)

It will show the IP Address used + the first and last time the IP was detected. 

By default the extension will not save the IP logs, so you will need to save the logs in a .txt format and when you open back Burp load them from that .txt file.
In case is the end of the exercise, you can export the logs as a CSV file and format the .csv as a table in an easy way.

<p>If you have any idea: https://github.com/e1abrador/Burp-IP-Tracker/pulls</p>
<p>If you have any issue with the extension: https://github.com/e1abrador/Burp-IP-Tracker/issues</p>

Good luck and good hunting!
If you really love the tool (or any others), or they helped you find an awesome bounty, consider [BUYING ME A COFFEE!](https://www.buymeacoffee.com/e1abrador) ☕ (I could use the caffeine!)

⚪ e1abrador

<a href='https://www.buymeacoffee.com/e1abrador' target='_blank'><img height='36' style='border:0px;height:36px;' src='https://storage.ko-fi.com/cdn/kofi2.png?v=3' border='0' alt='Buy Me a Coffee at ko-fi.com' /></a>

## TODO

- Implement a "CLEAR" button.
- Implement a "Export to CSV" button. [DONE]

## Thanks

Thanks to Ricardo Pelaz for the awesome idea!
- https://github.com/varandinawer
- https://twitter.com/Varandinawer

## Advisory

This Burp Suite extension should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.
