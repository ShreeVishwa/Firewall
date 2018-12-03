Implementation Details

As the firwall rules are set only once but are used more frequently when checking for the incoming packets, I decided to go with the implementatipn using a hashmap where I take each rule as a tuple and compute it's hash and store it in a set. Incase of the the rules which have ranges, I split the ranges into individual values using the for loop and compute the hash value of each. This might take a little longer time when the rules are set for the first time. When we enter the values for a packet as an input, then these values are put in the tuple, hashed and then the hash is compared with the existing values in the hashset. The retrival time of this process is O(1) which enables us to perform the accept_packet function over very large number of packets very efficiently. The code works for large ip ranges but is very inefficient.

Test Cases Covered

I have tested my code for all the values that are given as examples in this coding challenge.
I have tested my code for the edge cases by setting the extreme values for the ports and the ips as the firewall rules to check for off-by-1 errors.
I have tested my code for the case of all IP and all ports open. It takes a long time to compute because of the values that go through the while look. The code doesn't break. Dpending upon the memory limit of the compute engine, it may run out of memory.

Optimization

One major advantage of the design is that it can process any number of requests in a short span of time because of it's O(1) retrival, but comes at a cost of O(n) space complexity which is the major drawback or disadvantage of this design. There is a trade off between the time and the space complexity that comes with this design. Another major drawback in my design in the possibility of collisions which has not been handled.
Another design that I came up with as an improvization to this existing design is:
1) Instead of looping over all the ports in the range, we can easily find whether a port exists in one of the given ranges uisng the Binary Interval Tree.
2) Another improvization can be in the case of ip ranges. Instead of storing them as a hash we can use a trie to store all the ips in the range.

How to run the code:
1) Enter the path to rules file into the constructor
2) Enter the details for the packet to check if its allowed by calling the allow_packet function
3) Navigate into the folder where the file is present and run the command
    python firewall.py
