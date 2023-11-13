WireShark dissector for the PPPP protocol
===

WireShark dissector for the P2P protocol used by various IoT devices,
typically cheap Chinese IP cameras.

### Specification

An attempt to document the protocol (in addition to what is programmatically
"documented" in the dissector) can be found [here](PPPP.md).

### Usage

To use this dissector, put pppp_dissect.lua in your WireShark plugin folder.
See https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html if
you need assistance in finding the folder.

If your device uses "encrypted" traffic, the dissector needs to know the PSK
(pre-shared key) used for encryption. By default, the dissector checks the
three most commonly used PSK automatically, but if your device does not use any
of these, you must manually enter the proper PSK. This needs to be set as the
property `pppp.psk`. You can find this preference in the GUI by going to
Wireshark Preferences, selecting Protocols, and then selecting PPPP.

You can consult the [table of known PSKs](PPPP.md#pre-shared-key) to find the
PSK for your device. If your prefix is not listed in that table, you will need
to find the PSK some other way, typically be reverse-engineering an existing
app.

### Acknowledgements

I am standing on the shoulder of giants. This would not have been possible
without the work of Paul Marrapese (https://github.com/pmarrapese/iot) and
datenstau (https://github.com/datenstau/A9_PPPP). I am also very grateful to
[@Python1320](https://github.com/Python1320) who helped me early on with
providing information from a different device, which enabled me to make the
dissector more general.

In learning to write a Lua WireShark dissector, [this post](
https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html)
from Mika's tech blog was incredibly helpful.

In contrast to pmarrapese's dissector, this dissector also handles "encrypted"
traffic (this is really more of an obfuscation than proper encryption). Nor
does it rely on Wireshark Generic Dissector. This has both pros and cons. This
means that it works on macOS (which WSGD does not -- this was the driving force
for me starting from scratch instead of building on pmarrapese's dissector).
But it is (probably) executing much slower, since it uses the Lua script
engine.

### License

This code is licensed under the MIT license.
