( Compile the state transition used in every counter output. )
bsv-effect: advance u32 -- u32 ;
: advance 1 cell>u32 u32+ ;
