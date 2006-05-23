use strict;

use ExtUtils::MakeMaker qw(WriteMakefile prompt);


# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
     'NAME'          => 'Net::validMX',
     'DISTNAME'      => 'Net-validMX',
     'VERSION_FROM'  => 'lib/Net/validMX.pm',
     'PREREQ_PM'     => {
				'Net::DNS' => 0.53
                        },
     'linkext'       => { LINKTYPE=>'' },
     'dist'          => {'COMPRESS'=>'gzip', 'SUFFIX' => 'gz'}
);

package MY;

sub metafile {
        my $self    = shift;
        my $meta    = $self->SUPER::metafile_target(@_);
        my ($extra) = $self->echo('license: perl', 'META.yml', 1);
        return "$meta\t$extra\n";
}

print "\nvalidMX\n\n'make install' to install the module and program.\n";
