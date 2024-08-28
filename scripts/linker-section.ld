LINK_BASE = 0x0000;

ENTRY( Start )

SECTIONS
{
    . = LINK_BASE;
    .text : {
        . = LINK_BASE;
        *( .text$A );
        *( .text$B );
        *( .rdata* );
        *( .text$F );
        *( .text$P );
    }

    .eh_frame : {
        *( .eh_frame )
    }
}