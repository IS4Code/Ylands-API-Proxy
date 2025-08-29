# Ylands API Proxy

This program is an HTTPS server that upgrades requests made by early Ylands versions to be compatible with the existing API endpoints.
With this program, it is possible to run any Ylands version currently up to 0.7.0.45788.

#StopKillingGames

## How to use

There are no additional steps necessary to get it working other than to run the executable.

To download the alpha version of Ylands, locate the appropriate [manifest](https://steamdb.info/depot/298611/manifests/) and paste the command to download into the Steam console (opened by navigating to `steam://open/console` in the browser).

For a step-by-step guide, see [this video](https://www.youtube.com/watch?v=TqRI6SkSTm8).

Note that this program does not bypass online checks made by the game ‒ all official API endpoints still need to be available.

## How it works

When launched, the program modifies `%WINDIR%\system32\drivers\etc\hosts` to redirect `ylands-api.bistudio.com` to itself (it requires administrator permissions).
Then it starts a server that listens for all requests from the game.
All requests are modified to use the latest `clientVersion` (found in URL queries and JSON payloads), i.e. 2.4.0, and sent to the actual official API endpoints.

In case of issues running the program, please submit an issue with the full output of the program.
If the `hosts` file cannot be modified, a backup is stored at `%WINDIR%\system32\drivers\etc\hosts.bak`.
