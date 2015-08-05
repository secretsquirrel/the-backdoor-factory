;aPLib data decompressor for Apple II
;Peter Ferrie (peter.ferrie@gmail.com)
;assemble using ACME
;dst<src
!cpu 65c02
!to "aplib",plain
*=$800

init	=	0 ;set to 1 if you know the values
hiunp	=	0 ;unpacker entirely in high memory
hipak	=	0 ;packed data entirely in high memory (requires hiunp)
!if init {
  oep		=	$1234 ;first unpacked byte to run, you must set this by yourself
  orgoff	=	$1234 ;offset of first unpacked byte, you must set this by yourself
}
!if hiunp {
  hioff		=	$d000 ;address of unpacker in high memory, you can change this but leave room for packed data if hipak=1
  !if hipak {
    paksize	=	$1234 ;size of packed data, you must set this by yourself if hiunp=1
  }
} else {
  paksize	=	$1234 ;size of packed data, you must set this by yourself if hiunp=0
}

;unpacker variables, no need to change these
src	=	$0
dst	=	$2
ecx	=	$4
last	=	$6
tmp	=	$8
A1L	=	$3c
A1H	=	$3d
A2L	=	$3e
A2H	=	$3f
A4L	=	$42
A4H	=	$43
LCBANK2	=	$c083
MOVE	=	$fe2c

!if init {
	lda	#>pakoff ;packed data offset
	sta	src+1
	lda	#<pakoff
	sta	src
	lda	#>orgoff ;original unpacked data offset
	sta	dst+1
  !if (>(oep-1)=>orgoff) { ;oep = original entrypoint
	pha
  } else {
	lda	#>(oep-1)
	pha
  }
	lda	#<orgoff
	sta	dst
  !if (<(oep-1)=<orgoff) {
	pha
  } else {
	lda	#<(oep-1)
	pha
  }
}

unpack ;unpacker entrypoint
	ldx	#$80
	stz	ecx+1
!if hiunp {
	lda	#>literal
	sta	A1H
	lda	#<literal
	sta	A1L
  !if hipak {
	lda	#>pakoff+paksize ;packed data offset + packed data size
	sta	A2H
	lda	#<pakoff+paksize
	sta	A2L
  } else {
	lda	#>pakoff
	sta	A2H
	lda	#<pakoff
	sta	A2L
  }
	lda	#>hioff
	sta	A4H
	lda	#<hioff
	sta	A4L
	jsr	MOVE
	lda	LCBANK2
	lda	LCBANK2
	rts
;*=$d000
} else {
	jmp	literal

pakoff
	;place packed data here for low memory unpacking
*=pakoff+paksize
}

literal
	jsr	getput
	ldy	#2

nexttag
	jsr	getbit
	bcc	literal
	jsr	getbit
	bcc	codepair
	jsr	getbit
	bcs	onebyte
	jsr	getsrc
	lsr
	beq	donedepacking
	stz	ecx
	rol	ecx
	sta	last
	stz	last+1
	bra	domatch_with_2inc

getbit
	txa
	asl
	bne	.stillbitsleft
	jsr	getsrc
	rol

.stillbitsleft
	tax

donedepacking
	rts

onebyte
	ldy	#1
	sty	ecx
	iny
	lda	#$10

.getmorebits
	pha
	jsr	getbit
	pla
	rol
	bcc	.getmorebits
	stz	tmp+1
	bne	domatch
	jsr	putdst

linktag
	bra	nexttag

codepair
	jsr	getgamma
-	jsr	dececx
	dey
	bne	-
	tay
	ora	ecx+1
	bne	normalcodepair
	jsr	getgamma
	bra	domatch_lastpos

normalcodepair
	dey
	sty	last+1
	jsr	getsrc
	sta	last
	jsr	getgamma
	cpy	#$7d
	bcs	domatch_with_2inc
	cpy	#5
	bcs	domatch_with_inc
	lda	last
	bmi	domatch_new_lastpos
	tya
	bne	domatch_new_lastpos

domatch_with_2inc
	inc	ecx
	bne	domatch_with_inc
	inc	ecx+1

domatch_with_inc
	inc	ecx
	bne	domatch_new_lastpos
	inc	ecx+1

domatch_new_lastpos

domatch_lastpos
	ldy	#1
	lda	last+1
	sta	tmp+1
	lda	last

domatch
	sta	tmp
	lda	src+1
	pha
	lda	src
	pha
	lda	dst
	sec
	sbc	tmp
	sta	src
	lda	dst+1
	sbc	tmp+1
	sta	src+1
-	jsr	getput
	jsr	dececx
	ora	ecx+1
	bne	-
	pla
	sta	src
	pla
	sta	src+1
	bra	linktag

getgamma
	lda	#1
	sta	ecx
	stz	ecx+1

.getgammaloop
	jsr	getbit
	rol	ecx
	rol	ecx+1
	jsr	getbit
	bcs	.getgammaloop
	rts

dececx
	lda	ecx
	bne	+
	dec	ecx+1
+	dec
	sta	ecx
	rts

getput
	jsr	getsrc

putdst
	sta	(dst)
	inc	dst
	bne	+
	inc	dst+1
+	rts

getsrc
	lda	(src)
	inc	src
	bne	+
	inc	src+1
+	rts

!if hiunp {
pakoff
	;place packed data here for high memory unpacking
}
