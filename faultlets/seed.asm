;
; This examples uses a fixed random seed. This is appropriate to 
; replay experiments. The output of the DBG instruction should be 
; consistent on multiple runs of this faultlet in different 
; module loads. The output can be checked with the dmesg command.
;
       JMPZ   R0      INIT ; Check if already initialized.
DONE:  SET    100     R2
       RND    R2      R1   ; Fill R1 with a random number with modulo < 100
       DBG    R1      "random number is %d"
                           ; Rest of the packet handling code goes here.
      ACP                  ; Accept packet (finish processing). 
                           ; This avoids INIT being run again.

INIT:
       SET 1          R0   ; Flag that this code (INIT) has been run.
       SET 0xbabababa R4   ; Seed values for the Tausworthe RNG.
       SET 0xcacacaca R5 
       SET 0xdadadada R6 
       SEED R4 R5 R6       ; Seed.
       JMP DONE 
