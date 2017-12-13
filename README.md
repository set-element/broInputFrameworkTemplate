Sample code for reading structured text and converting it into native bro events.  

Example of similar code being called:

# This will run anything in the __load__.bro file located
#  in the isshd_policy directory
#
@load isshd_policy
#
# Where do we get the data from?
redef SSHD_IN_STREAM::data_file = "/data_s1/isshd/POINTER";

#
