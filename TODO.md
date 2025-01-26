# Seva

- fix up blog post for architecture
- write blog post about hash table implementation and some stuff i learned
- write blog post about parser state machine

- Do talk about the overall layers of data exchange and how I was able to cut some copying by ensuring certain properties e.g. the match function was thinking about a SECONDARY buffer for the rolling property but instead I can instead tell the network buffer layer to always guarantee a MAX_TOKEN_SIZE amount of data ahead of the position pointer and if it becomes less then copy remaining 8 bytes and refresh buffer.
- of course this will have to deal with stuff like EOF. no need to do that if EOF has been received.

there is a massive struggle trying to keep the copies as low as possible and optimizing. 

# DEFINITELY WRITE ABOUT THE RING_BUFFER and how I made it work with shm_create as well! And how you can make it agnostic
