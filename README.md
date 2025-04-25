# ProcessHollowing
A simple Process Hollowing poc written in c 

# IMPORTANT

THIS POC DOESN'T WORK

# What Is Process Hollowing

- Its A technique that is done in a couple of steps :
  
1 - Creating A process in a suspended state

2 - Parsing The PEB which contains infos about the process to get the base address which we will need later 

3 - Unmapping the base address using NtUnmapViewOfSection (that was resolved previously)

4 - Allocating space in the previously unmapped section then writing the injected pe into the base address

5 - Editing the eip reg (for x32) into the new entry point

6 - resuming the thread which executes our injected pe while keeping the same process pid

# Why do this 

this is a very common process injection technique it is used to evade some avs also might be used as a start to escalate privs 
# Was it hard ?

writing the poc wasn't hard nor understanding the logic and the theory behind it but actually getting it to work seemed like an impossible task which just made me give up and post it as it is broken
# Whats Wrong with it

well whenever i try to inject a 32 bit pe into a 32 bit process which is how its supposed to work it gives me an error (0xc0000141) everything else seemed find when i looked at the ouptut, i tried to analyse everything starting from the memory of the target process to the registers i also tried to debug it using x32dbg but no luck even ais like chat gpt didn't give me a solution so i just gave up and decided to move into something else and come back for this when i am actually ready and have enough knowledge to fix it

# Notes :

If you wanna try the poc make sure you change the paths inside it with 32bit target and pe 

i would really appreciate some help if anyone can tell whats wrong please contact me 

here are some possible causes that might be why it crashes and gives that error :

- not resolving the iat table (even tho i saw some codes online that didn't resolve it but still when i tried them i got the same error)

- a problem with my envi so if you try it and it works for you please enform me


# ScreenShot
<img width="1279" alt="processhollowing" src="https://github.com/user-attachments/assets/fb73f1d1-876f-4edf-8211-5b7fd0238055" />

--------------- 
# HACK THE PLANET
