( Advance the state and preserve the executing code in the successor. )
pels-amount: witness ;
: advance ( u32 -- u32 ) 1 cell>u32 u32+ ;
