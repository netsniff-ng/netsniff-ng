" Vim syntax file
" Language: Berkeley Packet Filter
" Maintainer: Daniel Borkmann
" Latest Revision: 08/16/2011

if exists("b:current_syntax")
  finish
endif

syn keyword bpfTodo contained TODO FIXME XXX NOTE FUBAR
syn keyword bpfKeywords ldb ldh ld ldx ldxb st stx jmp ja jeq jgt jge skipwhite
syn keyword bpfKeywords jset add sub mul div and or lsh rsh ret tax txa skipwhite

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

