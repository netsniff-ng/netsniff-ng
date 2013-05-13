" Vim syntax file
" Language: Berkeley Packet Filter
" Maintainer: Daniel Borkmann
" Latest Revision: 08/16/2011
"
" In order to make syntax highlighting for BPFs work in vim, copy this file
" to ~/.vim/syntax/ and activate it in vim by entering:
"
"    :set syntax=bpf
"
" If you want to automatically load the BPF syntax highlighting for *.bpf 
" files create the ~/.vim/filetype.vim with the following content:
"
"    my filetype file
"    if exists("did_load_filetypes")
"      finish
"    endif
"
"    augroup filetypedetect
"      au! BufRead,BufNewFile *.bpf  setfiletype bpf
"    augroup END
"

if exists("b:current_syntax")
  finish
endif

syn keyword bpfTodo contained TODO FIXME XXX NOTE
syn keyword bpfKeywords ldb ldh ld ldi ldx ldxi ldxb st stx jmp ja jeq jneq jne skipwhite
syn keyword bpfKeywords jlt jle jgt jge jset add sub mul div mod neg and or xor skipwhite
syn keyword bpfKeywords lsh rsh ret tax txa skipwhite

syn match bpfLabel /[a-zA-Z0-9_]\+/
syn match bpfSpChar /[:,#\[\]\(\)+*&]\?/ contains=bpfNumber,bpfLabel
syn match bpfNumber /\(0[xX]\x\+\|\d\+\)/
syn match bpfComment ";.*$" contains=bpfTodo

hi def link bpfTodo Todo
hi def link bpfComment Comment
hi def link bpfKeywords Keyword
hi def link bpfLabel Type
hi def link bpfNumber Number
hi def link bpfSpChar Special

let b:current_syntax = "bpf"
