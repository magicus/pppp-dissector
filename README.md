WireShark dissector for the PPPP protocol
===

WireShark dissector for the P2P protocol used by various IoT devices,
typically cheap Chinese IP cameras.

I am standing on the shoulder of giants. This would not have been possible
without the work of Paul Marrapese (https://github.com/pmarrapese/iot) and
datenstau (https://github.com/datenstau/A9_PPPP).

In learning to write a Lua WireShark dissector, [this post](
https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html)
from Mika's tech blog was incredibly helpful.

In contrast to pmarrapese, this dissector also handles "encrypted" traffic
(this is really more of an obfuscation than proper encryption). Nor does it
rely on Wireshark Generic Dissector. This has both pros and cons. This means
that it works on macOS (which WSGD does not -- this was the driving force
for me starting from scratch instead of building on pmarrapese's dissector).
But it is (probably) executing much slower, since it uses the Lua script engine.

To use this dissector, put pppp_dissect.lua in your WireShark plugin folder.
See https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html if
you need assistance in finding the folder.

This code is licensed under the MIT license.
