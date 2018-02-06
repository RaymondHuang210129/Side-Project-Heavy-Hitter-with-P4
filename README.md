# Heavy Hitter: High Load Internet Flow Detection
Study reference: https://dl.acm.org/citation.cfm?id=3063772

Realize the conception of Heavy Hitter with P4 Program without refering to tutorial. 

Version 1 (2/3):
 - fields to be hashed: source address in ipv4
 - fields stored in registers: source address, counts
 - Todos:
   - change the field to source adr, destination adr, src port, dest port to be hashed
   - store hash values in register rather than fields data -- reduce the space cost
   - reset table, return statistics, ...