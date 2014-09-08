/* dover */

/*  The version of crypt() used in the worm program has the same tables as
 * Berkeley's 4.3 crypt(), but uses different code.  Since I don't know where
 * we put our 4.2 tape I can't check it against that code to find the exact
 * source.  I assume that it just a regualar crypt() routine with several
 * interior functions declared static, perhaps tuned somewhat for speed on the
 * VAX and Sun.
 */
crypt()
{ }
    
/* These might not be copyrighted, but I'm not taking the chance.  They are
   obvious. */
h_addr2host()
{}
h_name2host()
{}

/*
 * Local variables:
 * compile-command: "make test"
 * comment-column: 48
 * End:
 */
