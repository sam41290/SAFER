use strict; 
use warnings; 
  
sub main 
{ 
    my $file = '/home/soumyakant/Documents/test'; 
    open(FH, $file) or die("File $file not found"); 
      
    while(my $String = <FH>) 
    { 
        if($String =~ /t..s/) 
        { 
            print "$String \n"; 
        } 
    } 
    close(FH); 
} 
main();
