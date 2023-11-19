# TomsRotaryCipher
This is a modern day Enigma machine that can be tested using "Test DLL TomsRotaryCipher1".

# Background
In 2015 I started a project after seeing videos of the Enigma machine, a state of the art device for the mid 1900s. The project started in VB and morphed into a password manager, featuring a virtual "rotary" containing 64 characters and unlimited rotors. I ran a test of 1 million virtual rotors, it worked, but ran for a very long time. 

In 2019, the main engine was re-written in C# as a DLL. The c# version uses a 256 position byte array; a wheel with 256 slots containing a pseudo random number from 0 to 255. The number of wheels is user-definable, with traditional Enigma and more modern logic to control how the wheels will "spin" and produce ciphertext. One of the last modules I implemented was a replication of the "Sigaba" skipping logic, which was an American adaptation to the German Enigma machine. I found this project enlightening and fun at the time. 

After years of letting this project gather dust, its time to release it into the wild and see if it ends up manipulating and changing other peoples' personal info. Of course, I will never know it even happened.

I kept a blog from the programs' inception in 2015 to 2019 when I stopped working on the project. The blog was never published, and details how I wrote code, my ideas about security, and what I learned while testing. It is amazing how much you can learn by throughly testing something like this! This blog was more for myself rather than public consumption, but I intented to release code back then, it just took a while:

https://homeitstuff.blogspot.com/

Please note, since the posts were being perpetually edited, you might end up reading them out of order. Some of the posts are refering to the original VB code with screen shots, and other posts refer to the current c# code.

# Change History

2024/11/19 https://homeitstuff.blogspot.com/2023/11/todays-changes.html

2024/11/12 https://homeitstuff.blogspot.com/2023/11/very-large-arrays-in-c.html

2024/11/11 https://homeitstuff.blogspot.com/2023/11/test-1-million-rotors-c-enigma.html

# Disclaimer
I tested this program enough to know it works as advertised. But please understand the limitations if you are going to use this for any real "security". I am a hobbist, not a crytologist. 
