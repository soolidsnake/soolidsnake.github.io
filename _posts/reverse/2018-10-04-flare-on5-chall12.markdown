---
layout: post
title:  "Flare-on challenge 12"
date:   2018-10-04 23:05:00 +0100
tag: reverse
---
## Please read the [disclaimer]({{ site.baseurl }}{% link 9.disclamer.md %})

    Now for the final test of your focus and dedication. 
    We found a floppy disk that was given to spies to transmit secret messages.
    he spies were also given the password, we don't have that information,
    but see if you can figure out the message anyway. 
    You are saving lives.


**Note**: I'm sorry the writeup is a bit messy, I couldn't find the time to write it properly, if you have any question please contact me, have fun :D
I will update it whenever I find some free time.

## Overview

We are provided with a 16bit DOS bootable system, it prints some messages then asks for a password, deeper withing the system, **2 virtual machines** are implemented, the first is implemented with [subleqs](https://en.wikipedia.org/wiki/One_instruction_set_computer#Subtract_and_branch_if_less_than_or_equal_to_zero) which role is to emulate the second VM, and the other one is implemented with [RSSB](https://en.wikipedia.org/wiki/One_instruction_set_computer#Reverse_subtract_and_skip_if_borrow).


## Setting up the environnement

I used [BOCHS](http://bochs.sourceforge.net) with **IDA** to run and debug the DOS system, to do that, you have to open **IDA** and choose **BOCHS** as debugger, then open this configuration file:
 
```
megs: 16

# hard disk
# ata0: enabled=1, ioaddr1=0x1f0, ioaddr2=0x3f0, irq=14

# floppy
floppya: type=1_44, 1_44="suspicious_floppy_v1.0.img", status=inserted

# what disk images will be used:

clock: sync=none

boot: floppy
panic: action=fatal
error: action=report
info: action=report
debug: action=ignore
```

## Reversing the DOS system part

The files of the system:

![system_files](/assets/img/flare-on/chall12/system_files.png)

I first noticed some helpful stuff, as you can see in this screenshot, **key.data** contains the previous input

![key_data](/assets/img/flare-on/chall12/key_data.png)

Also when reading **message.data** the same program that checks the password gets executed, this can hint that a certain **syscall** is **hooked**

![message_data](/assets/img/flare-on/chall12/message_data.png)

cool, now to the real stuff, let's use our debugger !

First we need to put a breakpoint in **0x7c00**, and start exploring the assembly code, briefly those are the most important part to know

- Reads input from STDIN
  
![read_input](/assets/img/flare-on/chall12/read_input.png)

- Open key.data and write input to it 

![write_to_key](/assets/img/flare-on/chall12/write_to_key.png)

- Open message.data and read from it, this is where the **syscall** is **triggered**, following the assembly code I ended up to a **INT 13h**, executing this interruption will read **TMP.data** and start executing its code.

![read_tmp_and_execute](/assets/img/flare-on/chall12/read_tmp_and_execute.png)

After some assembly instructions, I noticed that it copies input to a certain memory with unicode format

![copy_input](/assets/img/flare-on/chall12/copy_input.png)


Then the code enter to a loop which is the main engine of the subleq virtual machine located at **0x9d9d9**

![main_loop](/assets/img/flare-on/chall12/main_loop.png)

overview of the engine:

![graph_main_loop](/assets/img/flare-on/chall12/graph_main_loop.png)

in each iteration of the engine a certain function located at **0x9d99d** is called

![exec_subleq_instr](/assets/img/flare-on/chall12/exec_subleq_instr.png)

From the assembly code we can deduce that this is **subleq** VM.








To get a better control of the execution flow, I ported the assembly code to **C** code you can find the emulator in my github [subleq emulator](https://github.com/soolidsnake/Write-ups/blob/master/Flare-on5/Suspicious_Floppy/subleq_emulator.c)






Running the C program generates 150 millions subleq instructions, for this type of situation we can trace the instruction pointer of the virtual machine and draw a graph out of it

![graph_subleq_big](/assets/img/flare-on/chall12/graph_subleq_big.png)

Looking at the graph and with some past experience, we can suppose that subleq is actually emulating another virtual machine, let's see the graph in more detail

![graph_subleq](/assets/img/flare-on/chall12/graph_subleq.png)


As you can see the graph is constant, it always jump to the same addresses, our next goal is to figure our 2 things

- The base address of the second virtual machine
- The type of the second virtual machine

Before that, I had the idea of writing some higher level instructions out of the subleq instructions [subleq emulator higher instructions](https://github.com/soolidsnake/Write-ups/blob/master/Flare-on5/Suspicious_Floppy/subleq_emulator_high_instr.c)

looking through the subleqs translated to a higher level language and with the help of the graph, we can notice an interesting part

first iteration
![high_subleq_0](/assets/img/flare-on/chall12/high_subleq_0.png)

second iteration:
![high_subleq_1](/assets/img/flare-on/chall12/high_subleq_1.png)

third iteration:
![high_subleq_2](/assets/img/flare-on/chall12/high_subleq_2.png)


We can assume that the address `[010f]` contains the base address of the second vm which is `{07f6}`, looking a bit deeper we can notice other stuff like:

- A **pointer** at `[07f6]`, which is actually the offset pointer
- A value `{25b7}` is compared to that **pointer** 
- Data been copied from **[base_address + offset_pointer]** to **[0254]**
for example, the first iteration it copies data from **0x951**
the second one copies from **0x952**


Knowing that, we can focus on first the iterations to determine the type of the second VM.

First I compared the differences between each iteration to help me understand the flow. After that I enumerated everything that is happening in a single iteration then concluded that the second VM is actually using **RSSB**

to explain this with more details, I will take the second iteration as an example:



as you can see here, it does the following:

- Calculates the vm pointer by summing **base address** + **offset pointer**
- Mov the vm data(**0160**) pointed by the vm pointer to **0x0254**

![subleq_calculate_pointer_mov_data_rssb](/assets/img/flare-on/chall12/subleq_calculate_pointer_mov_data_rssb.png)

- Calculates another vm address(**0956**) by adding **base address(07f6)** + **vm_data(0160)** found earlier
- Mov data(**0002**) pointed by **0956** to **07ee**

![calculate_pointer_to_op_get_op](/assets/img/flare-on/chall12/calculate_pointer_to_op_get_op.png)

- Subtract that data(**0002**) from the content of **07ee**
- Mov the result to **07ee**

![subleq_sub_rssb](/assets/img/flare-on/chall12/subleq_sub_rssb.png)

This is enough to suppose that the second vm is using **RSSB**






Next, I dumped the data starting from the base address of the second vm **(07f6)**, and wrote a RSSB emulator to check either my supposition was correct or not, fortunately it was !
Here is my **C** code to emulate it [rssb emulator](https://github.com/soolidsnake/Write-ups/blob/master/Flare-on5/Suspicious_Floppy/rssb_emulator.c)





Our next goal is to figure out how the input is checked, but first an overview about what is happening is crucial so I made another graph

![rssb_graph](/assets/img/flare-on/chall12/rssb_graph.png)


With this we can divided our research in 3 parts according to the graph, each part is a loop with multiple iterations

## PART 0

By fuzzing with different input, I noticed something interesting, for example if you put **@** at the beginning of your input the **PART 0** executes less instructions compared if you put **@** at the end of your input.

![@_start](/assets/img/flare-on/chall12/@_start.png)

![@_pos_9](/assets/img/flare-on/chall12/@_pos_9.png)

Checking the RSSB instructions reveals that the supposition was correct to summarize it, it go through the input and check if **@** is present, if it does, it jumps to **PART1**

Here we can see that it subs my first character which was **'a' (0x61 in hex)** from **'@' (0x40 in hex)**

![rssb_check_@](/assets/img/flare-on/chall12/rssb_check_@.png)



## PART 1

This part is always present before **PART 2**, after reading its instructions I was able to come up with this expression: `input[i]-0x20 + ((input[i+1]-0x20) << 7)`
in each iteration **i** is incremented by 2, knowing that we have 15 of those iterations, we suppose that the password length is **30**

![calc_first_sec_char](/assets/img/flare-on/chall12/calc_first_sec_char.png)

## PART 2

This part is constant even with different input, it get executed only when **@** is present in the input, we can see **15** iterations of the same loop, so I assumed this is the part that **checks** the password

Digging deeper by reading the instructions and by arming my self with a lot of **patience**, I was able to understand the flow of the check, it performs sequentially the following operations:

- Xor the value calculated earlier: `input[i]-0x20 + ((input[i+1]-0x20) << 7)` with **iteration number of PART2** multiplied by **33**
- Calculate the **sum of the input characters** then add to it a value **dependent of number of chars before '@'**

![sum_chars_length_var](/assets/img/flare-on/chall12/sum_chars_length_var.png)

- Add the 2 values calculated

![add_A_B](/assets/img/flare-on/chall12/add_A_B.png)

- Compare result with a hardcoded hash

![check_with_hash](/assets/img/flare-on/chall12/check_with_hash.png)


A pseudo code for **PART1** and **PART2** would be:

{% highlight python linenos %}
correct = 1
iteration = 0
for i in range(0, len(password))-2, 2):
    A = (password[i] + (password[i+1]<<7)) ^ (iteration*33)
    B = sum_chars(password) + variable_dependent_of_length
    if A + B == hardcoded_hash:
        correct *= 1
    else:
        correct *= 0
    iteration += 1

if correct == 1:
    print 'success'
else:
    print 'error'
{% endhighlight %}




After extracting the 15 hashes, the goal is to bruteforce the characters 2 by 2, the only problem is that we don't have the sum of the password characters, so I supposed that the password ends with `@flare-on.com` we can use for example `om` to retrieve the sum, and then bruteforce the remaining characters:


{% highlight python linenos %}
import string
import itertools
from pwn import *

post_flag = '@flare-on.com'
flag_len = 30
summ = 0
length_var = 0x8400

hashes = [0xfc7f, 0xf30f, 0xf361, 0xf151,0xf886,0xf3d1,0xdb57,0xd9d5,0xe26e,0xf8cd,0xf969,0xd90c,0xf821,0xf181,0xf85f]

def pre_calc(a, b):
	return ((ord(a) - 0x20) + ((ord(b) - 0x20) << 7)&0xffff)

def get_sum(a):
	s = 0
	for i in a:
		s += ord(i)

A = pre_calc('o', 'm')^(33*14)
summ = hashes[14] - length_var - A

flag = ''

for i in xrange(flag_len/2):
	for combo in itertools.product(string.printable, repeat=2):
		A = pre_calc(combo[0], combo[1])^(33*i)
		B = summ + length_var
		
		if A + B == hashes[i]:
			flag += combo[0] + combo[1]

log.success('flag=> %s',flag)
{% endhighlight %}

![flag](/assets/img/flare-on/chall12/flag.png)


If you liked my writeup, please take a look at my [github repo](https://github.com/soolidsnake)