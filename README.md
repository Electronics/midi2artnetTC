# midi2artnetTC
rtpMidi Timecode to Artnet Timecode based off the rtpMidi server from pymidi.

Ideal for connecting qlab to Chamsys MagicQ or similar.

To connect (on a mac or using rtpMIDI on windows), create a new MIDI network session and manually add the IP of the computer/server running server.py on port 5051.
Should connect almost instantly giving positive feedback on the server commandline.

Then just send midi timecode over the new MIDI virtual interface and the server.py will send out the corresponding artnet timecode at the same framerate.

NB: It appears qlab (and possibly others) only seem to send out EVEN frames of timecode!

### Requirements

* Python 3
* Pymidi (get from pip)

