# TomsRotaryCipher
This is a modern day Enigma machine that can be tested using "Test DLL TomsRotaryCipher1".

# Background
In 2019 I started a project after seeing videos of the Enigma machime, a state of the art device for the 1900s. I decided to write a more robust version of this using a 256 position byte array; a wheel with 256 slots containing a pseudo random number from 0 to 255. The number of wheels is user-definable, with traditional Enigma and more modern logic to control how the wheels will "spin" and produce ciphertext. One of the last modules I implemented was a replication of the "Sigaba" skipping logic, which was an American adaptation to the German Enigma machine. I found this project enlightening and fun at the time. 

# Disclaimer
I tested this program enough to know it works as adverstised. But please understand the limitations if you are going to use this for any real  "security" functions. I am a hobbist, not a crytologist. 
