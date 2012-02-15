;
; Loop example. This typically shouldn't be done, but it is shown as 
; a test of the watchdog mechanism. 
;

START:  JMP START
        DRP           ; Unreachable code. No packets should be
                      ; actually dropped.
