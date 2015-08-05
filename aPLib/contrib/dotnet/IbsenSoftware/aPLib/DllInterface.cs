//
// aPLib compression library  -  the smaller the better :)
//
// C# wrapper
//
// Copyright (c) 1998-2009 by Joergen Ibsen / Jibz
// All Rights Reserved
//
// http://www.ibsensoftware.com/
//

namespace IbsenSoftware.aPLib
{
	using System.Runtime.InteropServices;

	public class DllInterface
	{
		// declare delegate type used for compression callback
		public delegate int CompressionCallback(
			int length,
			int slen,
			int dlen,
			int cbparam
		);

		[DllImport("aplib.dll")]
		public static extern int aP_pack(
			[In]  byte[] source,
			[Out] byte[] destination,
			      int length,
			[In]  byte[] workmem,
			      CompressionCallback callback,
			      int cbparam
		);

		[DllImport("aplib.dll")]
		public static extern int aP_workmem_size(int length);

		[DllImport("aplib.dll")]
		public static extern int aP_max_packed_size(int length);

		[DllImport("aplib.dll")]
		public static extern int aP_depack_asm(
			[In]  byte[] source,
			[Out] byte[] destination
		);

		[DllImport("aplib.dll")]
		public static extern int aP_depack_asm_fast(
			[In]  byte[] source,
			[Out] byte[] destination
		);

		[DllImport("aplib.dll")]
		public static extern int aP_depack_asm_safe(
			[In]  byte[] source,
			      int srclen,
			[Out] byte[] destination,
			      int dstlen
		);

		[DllImport("aplib.dll")]
		public static extern int aP_crc32([In] byte[] source, int length);

		[DllImport("aplib.dll")]
		public static extern int aPsafe_pack(
			[In]  byte[] source,
			[Out] byte[] destination,
			      int length,
			[In]  byte[] workmem,
			      CompressionCallback callback,
			      int cbparam
		);

		[DllImport("aplib.dll")]
		public static extern int aPsafe_check([In] byte[] source);

		[DllImport("aplib.dll")]
		public static extern int aPsafe_get_orig_size([In] byte[] source);

		[DllImport("aplib.dll")]
		public static extern int aPsafe_depack(
			[In]  byte[] source,
			      int srclen,
			[Out] byte[] destination,
			      int dstlen
		);
	}
}
