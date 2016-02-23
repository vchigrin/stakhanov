rem Hack for resetting =ExitCode env. variable to 0
reg /?
cl.exe -c main.cc /Fomymain.obj
link.exe mymain.obj /out:mytestexe.exe
