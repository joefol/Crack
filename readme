Usage
crack <threads> <keysize> <target>

Description
crack should attempt to find the password associated to the target DES hash. It does this by trying all possible lowercase alphabetic (a-z) passwords of length up to keysize. The program should run with threads concurrent threads for speed.

Linux/Unix user passwords are never stored on the system. Instead, a function called a hash is applied to the password. Then, the hashed password is stored, traditionally in /etc/passwd or more recently in /etc/shadow. The classic hash function on Unix systems is crypt(3). To make things harder on crackers, crypt also uses a two character string called a salt which it combines with the password to create the hash. Schematically:

password + salt => crypt() => hash

The salt is visible in the hash as the first two characters. As an example, a password 'apple' and salt 'na' become the hash 'na3C5487Wz4zw'.

The crack program should extract the salt from the first two characters of target, then repeatedly call crypt() using all possible passwords built of up to keysize lowercase alphabetic characters. For example, if the given keysize is four then your program would iterate over all strings 'aaaa', 'aaab', 'aaac', ..., 'zzzz' looking for one that hashes to the given input. If a match is not found, it would also look through all strings of length less than keysize.

When a match to target is found, the program should print the cracked password and exit immediately. If the entire space of passwords is searched with no match, the program should exit with no output.
