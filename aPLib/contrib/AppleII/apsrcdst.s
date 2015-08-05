;aPLib data decompressor for Apple II
;Peter Ferrie (peter.ferrie@gmail.com)
;assemble using ACME
;src<dst
!cpu 65c02
!to "aplib",plain
*=$800

init	=	0 ;set to 1 if you know the values
!if init {
  oep		=	$1234 ;first unpacked byte to run, you must set this by yourself
  orgoff	=	$1234 ;offset of first unpacked byte, you must set this by yourself
  orgsize	=	$1234 ;size of unpacked data, you must set this by yourself
  paksize	=	$1234 ;size of packed data, you must set this by yourself
}

;unpacker variables, no need to change these
src	=	$0
dst	=	$2
ecx	=	$4
last	=	$6
tmp	=	$8

!if init {
	lda	#>pakoff+paksize ;packed data offset + packed data size
	sta	src+1
	lda	#<pakoff+paksize
	sta	src
	lda	#>orgoff+orgsize ;original unpacked data offset + original unpacked size
	sta	dst+1
  !if (>(oep-1)=>(orgoff+orgsize)) { ;oep = original entrypoint
	pha
  } else {
	lda	#>(oep-1)
	pha
  }
	lda	#<orgoff+orgsize
	sta	dst
	lda	#<(oep-1)
	pha
}

unpack ;unpacker entrypoint
	ldx	#$80
	stz	ecx+1

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
	clc
	adc	tmp
	sta	src
	lda	dst+1
	adc	tmp+1
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
	pha
	lda	dst
	bne	+
	dec	dst+1
+	dec	dst
	pla
	sta	(dst)
	rts

getsrc
	lda	src
	bne	+
	dec	src+1
+	dec	src
	lda	(src)
	rts

pakoff
	;place packed data here
