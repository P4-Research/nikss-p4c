; ModuleID = 'out-xdp.c'
source_filename = "out-xdp.c"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf"

%struct.bpf_map_def = type { i32, i32, i32, i32, i32 }
%struct.xdp_md = type { i32, i32, i32, i32, i32 }
%struct.ingress_tbl_fwd_key = type { i32 }
%struct.ingress_tbl_fwd_value = type { i32, %union.anon }
%union.anon = type { %struct.anon }
%struct.anon = type { i32 }
%struct.headers = type { %struct.ethernet_t, %struct.ipv4_t }
%struct.ethernet_t = type { i64, i64, i16, i8 }
%struct.ipv4_t = type { i8, i8, i8, i16, i16, i8, i16, i8, i8, i16, i32, i32, i8 }

@tx_port = dso_local global %struct.bpf_map_def { i32 14, i32 4, i32 8, i32 64, i32 0 }, section "maps", align 4, !dbg !0
@ingress_tbl_fwd = dso_local global %struct.bpf_map_def { i32 1, i32 4, i32 8, i32 100, i32 0 }, section "maps", align 4, !dbg !33
@ingress_tbl_fwd_defaultAction = dso_local global %struct.bpf_map_def { i32 2, i32 4, i32 8, i32 1, i32 0 }, section "maps", align 4, !dbg !43
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1, !dbg !53
@llvm.used = appending global [8 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (%struct.bpf_map_def* @ingress_tbl_fwd to i8*), i8* bitcast (%struct.bpf_map_def* @ingress_tbl_fwd_defaultAction to i8*), i8* bitcast (i32 ()* @map_initialize to i8*), i8* bitcast (%struct.bpf_map_def* @tx_port to i8*), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_egress_func to i8*), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_ingress_func to i8*), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_redirect_dummy to i8*)], section "llvm.metadata"

; Function Attrs: nounwind
define dso_local i32 @map_initialize() #0 section "xdp/map-initializer" !dbg !107 {
  %1 = alloca i32, align 4
  %2 = alloca i64, align 8
  %3 = bitcast i32* %1 to i8*, !dbg !128
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %3) #5, !dbg !128
  call void @llvm.dbg.value(metadata i32 0, metadata !111, metadata !DIExpression()), !dbg !129
  store i32 0, i32* %1, align 4, !dbg !129, !tbaa !130
  %4 = bitcast i64* %2 to i8*, !dbg !134
  call void @llvm.lifetime.start.p0i8(i64 8, i8* nonnull %4) #5, !dbg !134
  store i64 0, i64* %2, align 8, !dbg !135
  %5 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i8* bitcast (%struct.bpf_map_def* @ingress_tbl_fwd_defaultAction to i8*), i8* nonnull %3, i8* nonnull %4, i64 0) #5, !dbg !136
  call void @llvm.dbg.value(metadata i32 undef, metadata !127, metadata !DIExpression()), !dbg !137
  call void @llvm.lifetime.end.p0i8(i64 8, i8* nonnull %4) #5, !dbg !138
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %3) #5, !dbg !138
  ret i32 0, !dbg !139
}

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1

; Function Attrs: nounwind readnone speculatable
declare void @llvm.dbg.declare(metadata, metadata, metadata) #2

; Function Attrs: argmemonly nounwind
declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1

; Function Attrs: nounwind
define dso_local i32 @xdp_ingress_func(%struct.xdp_md*) #0 section "xdp_ingress/xdp-ingress" !dbg !140 {
  %2 = alloca i64, align 8
  %3 = alloca i64, align 8
  %4 = alloca i16, align 8
  %5 = alloca i8, align 2
  %6 = alloca [37 x i8], align 1
  call void @llvm.dbg.declare(metadata i64* %2, metadata !147, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 64)), !dbg !240
  call void @llvm.dbg.declare(metadata i64* %3, metadata !147, metadata !DIExpression(DW_OP_LLVM_fragment, 64, 64)), !dbg !240
  call void @llvm.dbg.declare(metadata i16* %4, metadata !147, metadata !DIExpression(DW_OP_LLVM_fragment, 128, 16)), !dbg !240
  call void @llvm.dbg.declare(metadata i8* %5, metadata !147, metadata !DIExpression(DW_OP_LLVM_fragment, 144, 8)), !dbg !240
  call void @llvm.dbg.declare(metadata [37 x i8]* %6, metadata !147, metadata !DIExpression(DW_OP_LLVM_fragment, 152, 296)), !dbg !240
  %7 = alloca i32, align 4
  %8 = alloca %struct.ingress_tbl_fwd_key, align 4
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !144, metadata !DIExpression()), !dbg !241
  %9 = bitcast i64* %2 to i8*, !dbg !242
  call void @llvm.lifetime.start.p0i8(i64 8, i8* nonnull %9), !dbg !242
  %10 = bitcast i64* %3 to i8*, !dbg !242
  call void @llvm.lifetime.start.p0i8(i64 8, i8* nonnull %10), !dbg !242
  %11 = bitcast i16* %4 to i8*, !dbg !242
  call void @llvm.lifetime.start.p0i8(i64 2, i8* nonnull %11), !dbg !242
  call void @llvm.lifetime.start.p0i8(i64 1, i8* nonnull %5), !dbg !242
  %12 = getelementptr inbounds [37 x i8], [37 x i8]* %6, i64 0, i64 0, !dbg !242
  call void @llvm.lifetime.start.p0i8(i64 37, i8* nonnull %12), !dbg !242
  store volatile i64 0, i64* %2, align 8, !dbg !240
  store volatile i64 0, i64* %3, align 8, !dbg !240
  call void @llvm.memset.p0i8.i64(i8* nonnull align 8 %11, i8 0, i64 2, i1 true), !dbg !240
  call void @llvm.memset.p0i8.i64(i8* nonnull align 2 %5, i8 0, i64 1, i1 true), !dbg !240
  call void @llvm.memset.p0i8.i64(i8* nonnull align 1 %12, i8 0, i64 37, i1 true), !dbg !240
  call void @llvm.dbg.value(metadata i32 0, metadata !174, metadata !DIExpression()), !dbg !243
  call void @llvm.dbg.value(metadata i32 0, metadata !175, metadata !DIExpression()), !dbg !244
  call void @llvm.dbg.value(metadata i8 0, metadata !176, metadata !DIExpression()), !dbg !245
  %13 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !246
  %14 = load i32, i32* %13, align 4, !dbg !246, !tbaa !247
  %15 = zext i32 %14 to i64, !dbg !249
  %16 = inttoptr i64 %15 to i8*, !dbg !250
  call void @llvm.dbg.value(metadata i8* %16, metadata !177, metadata !DIExpression()), !dbg !251
  %17 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1, !dbg !252
  %18 = load i32, i32* %17, align 4, !dbg !252, !tbaa !253
  %19 = zext i32 %18 to i64, !dbg !254
  %20 = inttoptr i64 %19 to i8*, !dbg !255
  call void @llvm.dbg.value(metadata i8* %20, metadata !178, metadata !DIExpression()), !dbg !256
  %21 = bitcast i32* %7 to i8*, !dbg !257
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %21) #5, !dbg !257
  call void @llvm.dbg.value(metadata i32 0, metadata !179, metadata !DIExpression()), !dbg !258
  store i32 0, i32* %7, align 4, !dbg !258, !tbaa !130
  %22 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 3, !dbg !259
  %23 = load i32, i32* %22, align 4, !dbg !259, !tbaa !260
  call void @llvm.dbg.value(metadata i32 %23, metadata !181, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 32)), !dbg !261
  call void @llvm.dbg.value(metadata i8 0, metadata !181, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 8)), !dbg !261
  %24 = tail call i64 inttoptr (i64 5 to i64 ()*)() #5, !dbg !262
  call void @llvm.dbg.value(metadata i64 %24, metadata !181, metadata !DIExpression(DW_OP_LLVM_fragment, 64, 64)), !dbg !261
  call void @llvm.dbg.value(metadata i8 0, metadata !181, metadata !DIExpression(DW_OP_LLVM_fragment, 128, 8)), !dbg !261
  call void @llvm.dbg.value(metadata i32 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i32 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 72, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i8 1, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 96, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 104, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i16 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 112, 16)), !dbg !263
  %25 = getelementptr i8, i8* %16, i64 14, !dbg !264
  %26 = icmp ugt i8* %25, %20, !dbg !267
  br i1 %26, label %41, label %27, !dbg !268

; <label>:27:                                     ; preds = %1
  %28 = inttoptr i64 %15 to i64*, !dbg !269
  %29 = load i64, i64* %28, align 8, !dbg !269, !tbaa !270
  %30 = tail call i64 @llvm.bswap.i64(i64 %29), !dbg !269
  %31 = lshr i64 %30, 16, !dbg !272
  store volatile i64 %31, i64* %2, align 8, !dbg !273, !tbaa !274
  call void @llvm.dbg.value(metadata i32 48, metadata !174, metadata !DIExpression()), !dbg !243
  %32 = getelementptr inbounds i8, i8* %16, i64 6, !dbg !279
  %33 = bitcast i8* %32 to i64*, !dbg !279
  %34 = load i64, i64* %33, align 8, !dbg !279, !tbaa !270
  %35 = tail call i64 @llvm.bswap.i64(i64 %34), !dbg !279
  %36 = lshr i64 %35, 16, !dbg !280
  store volatile i64 %36, i64* %3, align 8, !dbg !281, !tbaa !282
  call void @llvm.dbg.value(metadata i32 96, metadata !174, metadata !DIExpression()), !dbg !243
  %37 = getelementptr inbounds i8, i8* %16, i64 12, !dbg !283
  %38 = bitcast i8* %37 to i16*, !dbg !283
  %39 = load i16, i16* %38, align 2, !dbg !283, !tbaa !284
  %40 = tail call i16 @llvm.bswap.i16(i16 %39)
  store volatile i16 %40, i16* %4, align 8, !dbg !285, !tbaa !286
  call void @llvm.dbg.value(metadata i32 112, metadata !174, metadata !DIExpression()), !dbg !243
  store volatile i8 1, i8* %5, align 2, !dbg !287, !tbaa !288
  br label %41, !dbg !289

; <label>:41:                                     ; preds = %1, %27
  %42 = phi i32 [ 14, %27 ], [ 0, %1 ]
  %43 = bitcast %struct.ingress_tbl_fwd_key* %8 to i8*, !dbg !290
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %43) #5, !dbg !290
  %44 = getelementptr inbounds %struct.ingress_tbl_fwd_key, %struct.ingress_tbl_fwd_key* %8, i64 0, i32 0, !dbg !291
  store i32 %23, i32* %44, align 4, !dbg !292, !tbaa !293
  call void @llvm.dbg.value(metadata %struct.ingress_tbl_fwd_value* null, metadata !214, metadata !DIExpression()), !dbg !295
  %45 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @ingress_tbl_fwd to i8*), i8* nonnull %43) #5, !dbg !296
  %46 = icmp eq i8* %45, null, !dbg !297
  br i1 %46, label %47, label %50, !dbg !299

; <label>:47:                                     ; preds = %41
  call void @llvm.dbg.value(metadata i8 0, metadata !205, metadata !DIExpression()), !dbg !300
  %48 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* bitcast (%struct.bpf_map_def* @ingress_tbl_fwd_defaultAction to i8*), i8* nonnull %21) #5, !dbg !301
  call void @llvm.dbg.value(metadata i8* %48, metadata !214, metadata !DIExpression()), !dbg !295
  call void @llvm.dbg.value(metadata i8* %48, metadata !214, metadata !DIExpression()), !dbg !295
  %49 = icmp eq i8* %48, null, !dbg !303
  br i1 %49, label %55, label %50, !dbg !305

; <label>:50:                                     ; preds = %41, %47
  %51 = phi i8* [ %48, %47 ], [ %45, %41 ]
  %52 = bitcast i8* %51 to i32*, !dbg !306
  %53 = load i32, i32* %52, align 4, !dbg !306, !tbaa !308
  switch i32 %53, label %55 [
    i32 1, label %56
    i32 0, label %54
  ], !dbg !310

; <label>:54:                                     ; preds = %50
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 104, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i32 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i32 %59, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 72, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 104, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i8 undef, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 96, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i32 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i32 %59, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 72, 8)), !dbg !263
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %43) #5, !dbg !311
  br label %141

; <label>:55:                                     ; preds = %50, %47
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 104, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i8 undef, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 96, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i32 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i32 %59, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 72, 8)), !dbg !263
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %43) #5, !dbg !311
  br label %141

; <label>:56:                                     ; preds = %50
  call void @llvm.dbg.value(metadata i32 0, metadata !207, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 32)), !dbg !312
  call void @llvm.dbg.value(metadata i32 0, metadata !207, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 32)), !dbg !312
  call void @llvm.dbg.value(metadata i8 0, metadata !207, metadata !DIExpression(DW_OP_LLVM_fragment, 72, 8)), !dbg !312
  call void @llvm.dbg.value(metadata i8 1, metadata !207, metadata !DIExpression(DW_OP_LLVM_fragment, 96, 8)), !dbg !312
  call void @llvm.dbg.value(metadata i8 0, metadata !207, metadata !DIExpression(DW_OP_LLVM_fragment, 104, 8)), !dbg !312
  call void @llvm.dbg.value(metadata i16 0, metadata !207, metadata !DIExpression(DW_OP_LLVM_fragment, 112, 16)), !dbg !312
  call void @llvm.dbg.value(metadata i8 0, metadata !207, metadata !DIExpression(DW_OP_LLVM_fragment, 96, 8)), !dbg !312
  call void @llvm.dbg.value(metadata i32 0, metadata !207, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 32)), !dbg !312
  %57 = getelementptr inbounds i8, i8* %51, i64 4, !dbg !313
  %58 = bitcast i8* %57 to i32*, !dbg !317
  %59 = load i32, i32* %58, align 4, !dbg !317, !tbaa !318
  call void @llvm.dbg.value(metadata i32 %59, metadata !207, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 32)), !dbg !312
  call void @llvm.dbg.value(metadata i32 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i32 %59, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 72, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 96, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 104, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i16 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 112, 16)), !dbg !263
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 104, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i32 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i32 %59, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 72, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 104, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i8 undef, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 96, 8)), !dbg !263
  call void @llvm.dbg.value(metadata i32 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i32 %59, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 32)), !dbg !263
  call void @llvm.dbg.value(metadata i8 0, metadata !191, metadata !DIExpression(DW_OP_LLVM_fragment, 72, 8)), !dbg !263
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %43) #5, !dbg !311
  call void @llvm.dbg.value(metadata i32 0, metadata !228, metadata !DIExpression()), !dbg !319
  %60 = load volatile i8, i8* %5, align 2, !dbg !320, !tbaa !288
  %61 = icmp eq i8 %60, 0, !dbg !322
  %62 = select i1 %61, i32 0, i32 14, !dbg !323
  %63 = sub nsw i32 %62, %42, !dbg !324
  call void @llvm.dbg.value(metadata i32 %63, metadata !229, metadata !DIExpression()), !dbg !325
  %64 = icmp eq i32 %63, 0, !dbg !326
  br i1 %64, label %69, label %65, !dbg !327

; <label>:65:                                     ; preds = %56
  call void @llvm.dbg.value(metadata i32 0, metadata !230, metadata !DIExpression()), !dbg !328
  %66 = call i64 inttoptr (i64 44 to i64 (%struct.xdp_md*, i32)*)(%struct.xdp_md* nonnull %0, i32 %63) #5, !dbg !329
  %67 = trunc i64 %66 to i32, !dbg !329
  call void @llvm.dbg.value(metadata i32 %67, metadata !230, metadata !DIExpression()), !dbg !328
  %68 = icmp eq i32 %67, 0, !dbg !330
  br i1 %68, label %69, label %141

; <label>:69:                                     ; preds = %56, %65
  %70 = load i32, i32* %13, align 4, !dbg !332, !tbaa !247
  %71 = zext i32 %70 to i64, !dbg !333
  %72 = inttoptr i64 %71 to i8*, !dbg !334
  call void @llvm.dbg.value(metadata i8* %72, metadata !177, metadata !DIExpression()), !dbg !251
  %73 = load i32, i32* %17, align 4, !dbg !335, !tbaa !253
  call void @llvm.dbg.value(metadata i32 0, metadata !174, metadata !DIExpression()), !dbg !243
  %74 = load volatile i8, i8* %5, align 2, !dbg !336, !tbaa !288
  %75 = icmp eq i8 %74, 0, !dbg !338
  br i1 %75, label %138, label %76, !dbg !339

; <label>:76:                                     ; preds = %69
  %77 = zext i32 %73 to i64, !dbg !340
  %78 = inttoptr i64 %77 to i8*, !dbg !341
  call void @llvm.dbg.value(metadata i8* %78, metadata !178, metadata !DIExpression()), !dbg !256
  %79 = getelementptr i8, i8* %72, i64 14, !dbg !342
  %80 = icmp ugt i8* %79, %78, !dbg !345
  br i1 %80, label %141, label %81, !dbg !346

; <label>:81:                                     ; preds = %76
  %82 = load volatile i64, i64* %2, align 8, !dbg !347, !tbaa !274
  %83 = shl i64 %82, 16, !dbg !347
  %84 = call i64 @llvm.bswap.i64(i64 %83), !dbg !347
  store volatile i64 %84, i64* %2, align 8, !dbg !348, !tbaa !274
  %85 = trunc i64 %84 to i8, !dbg !349
  call void @llvm.dbg.value(metadata i8 %85, metadata !180, metadata !DIExpression()), !dbg !350
  store i8 %85, i8* %72, align 1, !dbg !351, !tbaa !318
  %86 = getelementptr inbounds i8, i8* %9, i64 1, !dbg !353
  %87 = load i8, i8* %86, align 1, !dbg !353, !tbaa !318
  call void @llvm.dbg.value(metadata i8 %87, metadata !180, metadata !DIExpression()), !dbg !350
  %88 = getelementptr i8, i8* %72, i64 1, !dbg !354
  store i8 %87, i8* %88, align 1, !dbg !354, !tbaa !318
  %89 = getelementptr inbounds i8, i8* %9, i64 2, !dbg !356
  %90 = load i8, i8* %89, align 2, !dbg !356, !tbaa !318
  call void @llvm.dbg.value(metadata i8 %90, metadata !180, metadata !DIExpression()), !dbg !350
  %91 = getelementptr i8, i8* %72, i64 2, !dbg !357
  store i8 %90, i8* %91, align 1, !dbg !357, !tbaa !318
  %92 = getelementptr inbounds i8, i8* %9, i64 3, !dbg !359
  %93 = load i8, i8* %92, align 1, !dbg !359, !tbaa !318
  call void @llvm.dbg.value(metadata i8 %93, metadata !180, metadata !DIExpression()), !dbg !350
  %94 = getelementptr i8, i8* %72, i64 3, !dbg !360
  store i8 %93, i8* %94, align 1, !dbg !360, !tbaa !318
  %95 = getelementptr inbounds i8, i8* %9, i64 4, !dbg !362
  %96 = load i8, i8* %95, align 4, !dbg !362, !tbaa !318
  call void @llvm.dbg.value(metadata i8 %96, metadata !180, metadata !DIExpression()), !dbg !350
  %97 = getelementptr i8, i8* %72, i64 4, !dbg !363
  store i8 %96, i8* %97, align 1, !dbg !363, !tbaa !318
  %98 = getelementptr inbounds i8, i8* %9, i64 5, !dbg !365
  %99 = load i8, i8* %98, align 1, !dbg !365, !tbaa !318
  call void @llvm.dbg.value(metadata i8 %99, metadata !180, metadata !DIExpression()), !dbg !350
  %100 = getelementptr i8, i8* %72, i64 5, !dbg !366
  store i8 %99, i8* %100, align 1, !dbg !366, !tbaa !318
  call void @llvm.dbg.value(metadata i32 48, metadata !174, metadata !DIExpression()), !dbg !243
  %101 = load volatile i64, i64* %3, align 8, !dbg !368, !tbaa !282
  %102 = shl i64 %101, 16, !dbg !368
  %103 = call i64 @llvm.bswap.i64(i64 %102), !dbg !368
  store volatile i64 %103, i64* %3, align 8, !dbg !369, !tbaa !282
  %104 = trunc i64 %103 to i8, !dbg !370
  call void @llvm.dbg.value(metadata i8 %104, metadata !180, metadata !DIExpression()), !dbg !350
  %105 = getelementptr i8, i8* %72, i64 6, !dbg !371
  store i8 %104, i8* %105, align 1, !dbg !371, !tbaa !318
  %106 = getelementptr inbounds i8, i8* %10, i64 1, !dbg !373
  %107 = load i8, i8* %106, align 1, !dbg !373, !tbaa !318
  call void @llvm.dbg.value(metadata i8 %107, metadata !180, metadata !DIExpression()), !dbg !350
  %108 = getelementptr i8, i8* %72, i64 7, !dbg !374
  store i8 %107, i8* %108, align 1, !dbg !374, !tbaa !318
  %109 = getelementptr inbounds i8, i8* %10, i64 2, !dbg !376
  %110 = load i8, i8* %109, align 2, !dbg !376, !tbaa !318
  call void @llvm.dbg.value(metadata i8 %110, metadata !180, metadata !DIExpression()), !dbg !350
  %111 = getelementptr i8, i8* %72, i64 8, !dbg !377
  store i8 %110, i8* %111, align 1, !dbg !377, !tbaa !318
  %112 = getelementptr inbounds i8, i8* %10, i64 3, !dbg !379
  %113 = load i8, i8* %112, align 1, !dbg !379, !tbaa !318
  call void @llvm.dbg.value(metadata i8 %113, metadata !180, metadata !DIExpression()), !dbg !350
  %114 = getelementptr i8, i8* %72, i64 9, !dbg !380
  store i8 %113, i8* %114, align 1, !dbg !380, !tbaa !318
  %115 = getelementptr inbounds i8, i8* %10, i64 4, !dbg !382
  %116 = load i8, i8* %115, align 4, !dbg !382, !tbaa !318
  call void @llvm.dbg.value(metadata i8 %116, metadata !180, metadata !DIExpression()), !dbg !350
  %117 = getelementptr i8, i8* %72, i64 10, !dbg !383
  store i8 %116, i8* %117, align 1, !dbg !383, !tbaa !318
  %118 = getelementptr inbounds i8, i8* %10, i64 5, !dbg !385
  %119 = load i8, i8* %118, align 1, !dbg !385, !tbaa !318
  call void @llvm.dbg.value(metadata i8 %119, metadata !180, metadata !DIExpression()), !dbg !350
  %120 = getelementptr i8, i8* %72, i64 11, !dbg !386
  store i8 %119, i8* %120, align 1, !dbg !386, !tbaa !318
  call void @llvm.dbg.value(metadata i32 96, metadata !174, metadata !DIExpression()), !dbg !243
  %121 = load volatile i16, i16* %4, align 8, !dbg !388, !tbaa !286
  %122 = call i1 @llvm.is.constant.i16(i16 %121), !dbg !388
  %123 = load volatile i16, i16* %4, align 8, !dbg !388, !tbaa !286
  br i1 %122, label %124, label %129, !dbg !388

; <label>:124:                                    ; preds = %81
  %125 = shl i16 %123, 8, !dbg !388
  %126 = load volatile i16, i16* %4, align 8, !dbg !388, !tbaa !286
  %127 = lshr i16 %126, 8, !dbg !388
  %128 = or i16 %127, %125, !dbg !388
  br label %131, !dbg !388

; <label>:129:                                    ; preds = %81
  %130 = call i16 @llvm.bswap.i16(i16 %123), !dbg !388
  br label %131, !dbg !388

; <label>:131:                                    ; preds = %129, %124
  %132 = phi i16 [ %128, %124 ], [ %130, %129 ]
  store volatile i16 %132, i16* %4, align 8, !dbg !389, !tbaa !286
  %133 = trunc i16 %132 to i8, !dbg !390
  call void @llvm.dbg.value(metadata i8 %133, metadata !180, metadata !DIExpression()), !dbg !350
  %134 = getelementptr i8, i8* %72, i64 12, !dbg !391
  store i8 %133, i8* %134, align 1, !dbg !391, !tbaa !318
  %135 = getelementptr inbounds i8, i8* %11, i64 1, !dbg !393
  %136 = load i8, i8* %135, align 1, !dbg !393, !tbaa !318
  call void @llvm.dbg.value(metadata i8 %136, metadata !180, metadata !DIExpression()), !dbg !350
  %137 = getelementptr i8, i8* %72, i64 13, !dbg !394
  store i8 %136, i8* %137, align 1, !dbg !394, !tbaa !318
  call void @llvm.dbg.value(metadata i32 96, metadata !174, metadata !DIExpression(DW_OP_plus_uconst, 16, DW_OP_stack_value)), !dbg !243
  br label %138, !dbg !396

; <label>:138:                                    ; preds = %131, %69
  %139 = call i64 inttoptr (i64 51 to i64 (i8*, i32, i64)*)(i8* bitcast (%struct.bpf_map_def* @tx_port to i8*), i32 %59, i64 0) #5, !dbg !397
  %140 = trunc i64 %139 to i32, !dbg !397
  br label %141, !dbg !398

; <label>:141:                                    ; preds = %65, %76, %54, %55, %138
  %142 = phi i32 [ %140, %138 ], [ 0, %55 ], [ 0, %54 ], [ 0, %76 ], [ 0, %65 ], !dbg !399
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %21) #5, !dbg !400
  call void @llvm.lifetime.end.p0i8(i64 8, i8* nonnull %9), !dbg !400
  call void @llvm.lifetime.end.p0i8(i64 8, i8* nonnull %10), !dbg !400
  call void @llvm.lifetime.end.p0i8(i64 2, i8* nonnull %11), !dbg !400
  call void @llvm.lifetime.end.p0i8(i64 1, i8* nonnull %5), !dbg !400
  call void @llvm.lifetime.end.p0i8(i64 37, i8* nonnull %12), !dbg !400
  ret i32 %142, !dbg !400
}

; Function Attrs: argmemonly nounwind
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1) #1

; Function Attrs: nounwind readnone speculatable
declare i64 @llvm.bswap.i64(i64) #2

; Function Attrs: nounwind readnone
declare i1 @llvm.is.constant.i16(i16) #3

; Function Attrs: nounwind readnone speculatable
declare i16 @llvm.bswap.i16(i16) #2

; Function Attrs: nounwind
define dso_local i32 @xdp_egress_func(%struct.xdp_md* nocapture readnone) #0 section "xdp_devmap/xdp-egress" !dbg !401 {
  %2 = alloca %struct.headers, align 8
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !403, metadata !DIExpression()), !dbg !443
  call void @llvm.dbg.value(metadata i32 0, metadata !404, metadata !DIExpression()), !dbg !444
  call void @llvm.dbg.value(metadata i32 0, metadata !405, metadata !DIExpression()), !dbg !445
  call void @llvm.dbg.value(metadata i8 0, metadata !406, metadata !DIExpression()), !dbg !446
  call void @llvm.dbg.value(metadata i32 0, metadata !409, metadata !DIExpression()), !dbg !447
  call void @llvm.dbg.value(metadata i8 0, metadata !411, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 8)), !dbg !448
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !411, metadata !DIExpression(DW_OP_plus_uconst, 12, DW_OP_deref, DW_OP_stack_value, DW_OP_LLVM_fragment, 32, 32)), !dbg !448
  call void @llvm.dbg.value(metadata i8 0, metadata !411, metadata !DIExpression(DW_OP_LLVM_fragment, 64, 8)), !dbg !448
  call void @llvm.dbg.value(metadata i16 0, metadata !411, metadata !DIExpression(DW_OP_LLVM_fragment, 80, 16)), !dbg !448
  %3 = tail call i64 inttoptr (i64 5 to i64 ()*)() #5, !dbg !449
  call void @llvm.dbg.value(metadata i64 %3, metadata !411, metadata !DIExpression(DW_OP_LLVM_fragment, 128, 64)), !dbg !448
  call void @llvm.dbg.value(metadata i8 0, metadata !411, metadata !DIExpression(DW_OP_LLVM_fragment, 192, 8)), !dbg !448
  call void @llvm.dbg.value(metadata i8 0, metadata !421, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 8)), !dbg !450
  call void @llvm.dbg.value(metadata i8 0, metadata !421, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 8)), !dbg !450
  %4 = bitcast %struct.headers* %2 to i8*, !dbg !451
  call void @llvm.lifetime.start.p0i8(i64 56, i8* nonnull %4), !dbg !451
  call void @llvm.memset.p0i8.i64(i8* nonnull align 8 %4, i8 0, i64 56, i1 true), !dbg !452
  call void @llvm.dbg.value(metadata i32 0, metadata !404, metadata !DIExpression()), !dbg !444
  call void @llvm.lifetime.end.p0i8(i64 56, i8* nonnull %4), !dbg !453
  ret i32 2, !dbg !453
}

; Function Attrs: norecurse nounwind readnone
define dso_local i32 @xdp_redirect_dummy(%struct.xdp_md* nocapture readnone) #4 section "xdp_redirect_dummy_sec" !dbg !454 {
  call void @llvm.dbg.value(metadata %struct.xdp_md* undef, metadata !456, metadata !DIExpression()), !dbg !457
  ret i32 2, !dbg !458
}

; Function Attrs: nounwind readnone speculatable
declare void @llvm.dbg.value(metadata, metadata, metadata) #2

attributes #0 = { nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { argmemonly nounwind }
attributes #2 = { nounwind readnone speculatable }
attributes #3 = { nounwind readnone }
attributes #4 = { norecurse nounwind readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #5 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!103, !104, !105}
!llvm.ident = !{!106}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "tx_port", scope: !2, file: !3, line: 62, type: !35, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "clang version 8.0.1-9 (tags/RELEASE_801/final)", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, retainedTypes: !14, globals: !32, nameTableKind: None)
!3 = !DIFile(filename: "out-xdp.c", directory: "/home/p4aas/p4aasWorkspace/p4c-ebpf-psa/backends/ebpf/evaluation/test_xdp")
!4 = !{!5}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "xdp_action", file: !6, line: 3150, baseType: !7, size: 32, elements: !8)
!6 = !DIFile(filename: "/usr/include/linux/bpf.h", directory: "")
!7 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!8 = !{!9, !10, !11, !12, !13}
!9 = !DIEnumerator(name: "XDP_ABORTED", value: 0, isUnsigned: true)
!10 = !DIEnumerator(name: "XDP_DROP", value: 1, isUnsigned: true)
!11 = !DIEnumerator(name: "XDP_PASS", value: 2, isUnsigned: true)
!12 = !DIEnumerator(name: "XDP_TX", value: 3, isUnsigned: true)
!13 = !DIEnumerator(name: "XDP_REDIRECT", value: 4, isUnsigned: true)
!14 = !{!15, !16, !17, !20, !21, !24, !26, !28, !29, !30}
!15 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!16 = !DIBasicType(name: "long int", size: 64, encoding: DW_ATE_signed)
!17 = !DIDerivedType(tag: DW_TAG_typedef, name: "u64", file: !18, line: 33, baseType: !19)
!18 = !DIFile(filename: "../../runtime/ebpf_common.h", directory: "/home/p4aas/p4aasWorkspace/p4c-ebpf-psa/backends/ebpf/evaluation/test_xdp")
!19 = !DIBasicType(name: "long long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !17, size: 64)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DIDerivedType(tag: DW_TAG_typedef, name: "u8", file: !18, line: 27, baseType: !23)
!23 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!24 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u64", file: !25, line: 31, baseType: !19)
!25 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "")
!26 = !DIDerivedType(tag: DW_TAG_typedef, name: "u16", file: !18, line: 29, baseType: !27)
!27 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!28 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !26, size: 64)
!29 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u16", file: !25, line: 24, baseType: !27)
!30 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !31, size: 64)
!31 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!32 = !{!0, !33, !43, !45, !51, !53, !58, !66, !71, !76, !84, !98}
!33 = !DIGlobalVariableExpression(var: !34, expr: !DIExpression())
!34 = distinct !DIGlobalVariable(name: "ingress_tbl_fwd", scope: !2, file: !3, line: 70, type: !35, isLocal: false, isDefinition: true)
!35 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_map_def", file: !36, line: 108, size: 160, elements: !37)
!36 = !DIFile(filename: "./p4-libbpf/src/bpf_helpers.h", directory: "/home/p4aas/p4aasWorkspace/p4c-ebpf-psa/backends/ebpf/evaluation/test_xdp")
!37 = !{!38, !39, !40, !41, !42}
!38 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !35, file: !36, line: 109, baseType: !7, size: 32)
!39 = !DIDerivedType(tag: DW_TAG_member, name: "key_size", scope: !35, file: !36, line: 110, baseType: !7, size: 32, offset: 32)
!40 = !DIDerivedType(tag: DW_TAG_member, name: "value_size", scope: !35, file: !36, line: 111, baseType: !7, size: 32, offset: 64)
!41 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !35, file: !36, line: 112, baseType: !7, size: 32, offset: 96)
!42 = !DIDerivedType(tag: DW_TAG_member, name: "map_flags", scope: !35, file: !36, line: 113, baseType: !7, size: 32, offset: 128)
!43 = !DIGlobalVariableExpression(var: !44, expr: !DIExpression())
!44 = distinct !DIGlobalVariable(name: "ingress_tbl_fwd_defaultAction", scope: !2, file: !3, line: 71, type: !35, isLocal: false, isDefinition: true)
!45 = !DIGlobalVariableExpression(var: !46, expr: !DIExpression(DW_OP_constu, 0, DW_OP_stack_value))
!46 = distinct !DIGlobalVariable(name: "NoError", scope: !2, file: !47, line: 28, type: !48, isLocal: true, isDefinition: true)
!47 = !DIFile(filename: "../../runtime/psa.h", directory: "/home/p4aas/p4aasWorkspace/p4c-ebpf-psa/backends/ebpf/evaluation/test_xdp")
!48 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !49)
!49 = !DIDerivedType(tag: DW_TAG_typedef, name: "ParserError_t", file: !47, line: 27, baseType: !50)
!50 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u8", file: !25, line: 21, baseType: !23)
!51 = !DIGlobalVariableExpression(var: !52, expr: !DIExpression(DW_OP_constu, 1, DW_OP_stack_value))
!52 = distinct !DIGlobalVariable(name: "PacketTooShort", scope: !2, file: !47, line: 29, type: !48, isLocal: true, isDefinition: true)
!53 = !DIGlobalVariableExpression(var: !54, expr: !DIExpression())
!54 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 355, type: !55, isLocal: false, isDefinition: true)
!55 = !DICompositeType(tag: DW_TAG_array_type, baseType: !31, size: 32, elements: !56)
!56 = !{!57}
!57 = !DISubrange(count: 4)
!58 = !DIGlobalVariableExpression(var: !59, expr: !DIExpression())
!59 = distinct !DIGlobalVariable(name: "bpf_map_update_elem", scope: !2, file: !60, line: 73, type: !61, isLocal: true, isDefinition: true)
!60 = !DIFile(filename: "./p4-libbpf/src/bpf_helper_defs.h", directory: "/home/p4aas/p4aasWorkspace/p4c-ebpf-psa/backends/ebpf/evaluation/test_xdp")
!61 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !62, size: 64)
!62 = !DISubroutineType(types: !63)
!63 = !{!16, !15, !64, !64, !24}
!64 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !65, size: 64)
!65 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!66 = !DIGlobalVariableExpression(var: !67, expr: !DIExpression())
!67 = distinct !DIGlobalVariable(name: "bpf_ktime_get_ns", scope: !2, file: !60, line: 109, type: !68, isLocal: true, isDefinition: true)
!68 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !69, size: 64)
!69 = !DISubroutineType(types: !70)
!70 = !{!24}
!71 = !DIGlobalVariableExpression(var: !72, expr: !DIExpression())
!72 = distinct !DIGlobalVariable(name: "bpf_map_lookup_elem", scope: !2, file: !60, line: 51, type: !73, isLocal: true, isDefinition: true)
!73 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !74, size: 64)
!74 = !DISubroutineType(types: !75)
!75 = !{!15, !15, !64}
!76 = !DIGlobalVariableExpression(var: !77, expr: !DIExpression())
!77 = distinct !DIGlobalVariable(name: "bpf_trace_printk", scope: !2, file: !60, line: 172, type: !78, isLocal: true, isDefinition: true)
!78 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !79, size: 64)
!79 = !DISubroutineType(types: !80)
!80 = !{!16, !81, !83, null}
!81 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !82, size: 64)
!82 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !31)
!83 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !25, line: 27, baseType: !7)
!84 = !DIGlobalVariableExpression(var: !85, expr: !DIExpression())
!85 = distinct !DIGlobalVariable(name: "bpf_xdp_adjust_head", scope: !2, file: !60, line: 1120, type: !86, isLocal: true, isDefinition: true)
!86 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !87, size: 64)
!87 = !DISubroutineType(types: !88)
!88 = !{!16, !89, !97}
!89 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !90, size: 64)
!90 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !6, line: 3161, size: 160, elements: !91)
!91 = !{!92, !93, !94, !95, !96}
!92 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !90, file: !6, line: 3162, baseType: !83, size: 32)
!93 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !90, file: !6, line: 3163, baseType: !83, size: 32, offset: 32)
!94 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !90, file: !6, line: 3164, baseType: !83, size: 32, offset: 64)
!95 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !90, file: !6, line: 3166, baseType: !83, size: 32, offset: 96)
!96 = !DIDerivedType(tag: DW_TAG_member, name: "rx_queue_index", scope: !90, file: !6, line: 3167, baseType: !83, size: 32, offset: 128)
!97 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!98 = !DIGlobalVariableExpression(var: !99, expr: !DIExpression())
!99 = distinct !DIGlobalVariable(name: "bpf_redirect_map", scope: !2, file: !60, line: 1288, type: !100, isLocal: true, isDefinition: true)
!100 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !101, size: 64)
!101 = !DISubroutineType(types: !102)
!102 = !{!16, !15, !83, !24}
!103 = !{i32 2, !"Dwarf Version", i32 4}
!104 = !{i32 2, !"Debug Info Version", i32 3}
!105 = !{i32 1, !"wchar_size", i32 4}
!106 = !{!"clang version 8.0.1-9 (tags/RELEASE_801/final)"}
!107 = distinct !DISubprogram(name: "map_initialize", scope: !3, file: !3, line: 75, type: !108, scopeLine: 75, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !110)
!108 = !DISubroutineType(types: !109)
!109 = !{!97}
!110 = !{!111, !113, !127}
!111 = !DILocalVariable(name: "ebpf_zero", scope: !107, file: !3, line: 76, type: !112)
!112 = !DIDerivedType(tag: DW_TAG_typedef, name: "u32", file: !18, line: 31, baseType: !7)
!113 = !DILocalVariable(name: "value_0", scope: !107, file: !3, line: 77, type: !114)
!114 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ingress_tbl_fwd_value", file: !3, line: 51, size: 64, elements: !115)
!115 = !{!116, !117}
!116 = !DIDerivedType(tag: DW_TAG_member, name: "action", scope: !114, file: !3, line: 52, baseType: !7, size: 32)
!117 = !DIDerivedType(tag: DW_TAG_member, name: "u", scope: !114, file: !3, line: 59, baseType: !118, size: 32, offset: 32)
!118 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !114, file: !3, line: 53, size: 32, elements: !119)
!119 = !{!120, !124}
!120 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_do_forward", scope: !118, file: !3, line: 56, baseType: !121, size: 32)
!121 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !118, file: !3, line: 54, size: 32, elements: !122)
!122 = !{!123}
!123 = !DIDerivedType(tag: DW_TAG_member, name: "egress_port", scope: !121, file: !3, line: 55, baseType: !112, size: 32)
!124 = !DIDerivedType(tag: DW_TAG_member, name: "_NoAction", scope: !118, file: !3, line: 58, baseType: !125)
!125 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !118, file: !3, line: 57, elements: !126)
!126 = !{}
!127 = !DILocalVariable(name: "ret", scope: !107, file: !3, line: 81, type: !97)
!128 = !DILocation(line: 76, column: 5, scope: !107)
!129 = !DILocation(line: 76, column: 9, scope: !107)
!130 = !{!131, !131, i64 0}
!131 = !{!"int", !132, i64 0}
!132 = !{!"omnipotent char", !133, i64 0}
!133 = !{!"Simple C/C++ TBAA"}
!134 = !DILocation(line: 77, column: 5, scope: !107)
!135 = !DILocation(line: 77, column: 34, scope: !107)
!136 = !DILocation(line: 81, column: 15, scope: !107)
!137 = !DILocation(line: 81, column: 9, scope: !107)
!138 = !DILocation(line: 87, column: 1, scope: !107)
!139 = !DILocation(line: 86, column: 5, scope: !107)
!140 = distinct !DISubprogram(name: "xdp_ingress_func", scope: !3, file: !3, line: 90, type: !141, scopeLine: 90, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !143)
!141 = !DISubroutineType(types: !142)
!142 = !{!97, !89}
!143 = !{!144, !145, !147, !174, !175, !176, !177, !178, !179, !180, !181, !191, !205, !207, !208, !214, !216, !224, !228, !229, !230, !233}
!144 = !DILocalVariable(name: "skb", arg: 1, scope: !140, file: !3, line: 90, type: !89)
!145 = !DILocalVariable(name: "resubmit_meta", scope: !140, file: !3, line: 91, type: !146)
!146 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "empty_t", file: !3, line: 37, elements: !126)
!147 = !DILocalVariable(name: "parsed_hdr", scope: !140, file: !3, line: 93, type: !148)
!148 = !DIDerivedType(tag: DW_TAG_volatile_type, baseType: !149)
!149 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "headers", file: !3, line: 42, size: 448, elements: !150)
!150 = !{!151, !158}
!151 = !DIDerivedType(tag: DW_TAG_member, name: "ethernet", scope: !149, file: !3, line: 43, baseType: !152, size: 192)
!152 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ethernet_t", file: !3, line: 14, size: 192, elements: !153)
!153 = !{!154, !155, !156, !157}
!154 = !DIDerivedType(tag: DW_TAG_member, name: "dstAddr", scope: !152, file: !3, line: 15, baseType: !17, size: 64)
!155 = !DIDerivedType(tag: DW_TAG_member, name: "srcAddr", scope: !152, file: !3, line: 16, baseType: !17, size: 64, offset: 64)
!156 = !DIDerivedType(tag: DW_TAG_member, name: "etherType", scope: !152, file: !3, line: 17, baseType: !26, size: 16, offset: 128)
!157 = !DIDerivedType(tag: DW_TAG_member, name: "ebpf_valid", scope: !152, file: !3, line: 18, baseType: !22, size: 8, offset: 144)
!158 = !DIDerivedType(tag: DW_TAG_member, name: "ipv4", scope: !149, file: !3, line: 44, baseType: !159, size: 224, offset: 192)
!159 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ipv4_t", file: !3, line: 20, size: 224, elements: !160)
!160 = !{!161, !162, !163, !164, !165, !166, !167, !168, !169, !170, !171, !172, !173}
!161 = !DIDerivedType(tag: DW_TAG_member, name: "version", scope: !159, file: !3, line: 21, baseType: !22, size: 8)
!162 = !DIDerivedType(tag: DW_TAG_member, name: "ihl", scope: !159, file: !3, line: 22, baseType: !22, size: 8, offset: 8)
!163 = !DIDerivedType(tag: DW_TAG_member, name: "diffserv", scope: !159, file: !3, line: 23, baseType: !22, size: 8, offset: 16)
!164 = !DIDerivedType(tag: DW_TAG_member, name: "totalLen", scope: !159, file: !3, line: 24, baseType: !26, size: 16, offset: 32)
!165 = !DIDerivedType(tag: DW_TAG_member, name: "identification", scope: !159, file: !3, line: 25, baseType: !26, size: 16, offset: 48)
!166 = !DIDerivedType(tag: DW_TAG_member, name: "flags", scope: !159, file: !3, line: 26, baseType: !22, size: 8, offset: 64)
!167 = !DIDerivedType(tag: DW_TAG_member, name: "fragOffset", scope: !159, file: !3, line: 27, baseType: !26, size: 16, offset: 80)
!168 = !DIDerivedType(tag: DW_TAG_member, name: "ttl", scope: !159, file: !3, line: 28, baseType: !22, size: 8, offset: 96)
!169 = !DIDerivedType(tag: DW_TAG_member, name: "protocol", scope: !159, file: !3, line: 29, baseType: !22, size: 8, offset: 104)
!170 = !DIDerivedType(tag: DW_TAG_member, name: "hdrChecksum", scope: !159, file: !3, line: 30, baseType: !26, size: 16, offset: 112)
!171 = !DIDerivedType(tag: DW_TAG_member, name: "srcAddr", scope: !159, file: !3, line: 31, baseType: !112, size: 32, offset: 128)
!172 = !DIDerivedType(tag: DW_TAG_member, name: "dstAddr", scope: !159, file: !3, line: 32, baseType: !112, size: 32, offset: 160)
!173 = !DIDerivedType(tag: DW_TAG_member, name: "ebpf_valid", scope: !159, file: !3, line: 33, baseType: !22, size: 8, offset: 192)
!174 = !DILocalVariable(name: "ebpf_packetOffsetInBits", scope: !140, file: !3, line: 102, type: !7)
!175 = !DILocalVariable(name: "ebpf_packetOffsetInBits_save", scope: !140, file: !3, line: 102, type: !7)
!176 = !DILocalVariable(name: "ebpf_errorCode", scope: !140, file: !3, line: 103, type: !49)
!177 = !DILocalVariable(name: "pkt", scope: !140, file: !3, line: 104, type: !15)
!178 = !DILocalVariable(name: "ebpf_packetEnd", scope: !140, file: !3, line: 105, type: !15)
!179 = !DILocalVariable(name: "ebpf_zero", scope: !140, file: !3, line: 106, type: !112)
!180 = !DILocalVariable(name: "ebpf_byte", scope: !140, file: !3, line: 107, type: !23)
!181 = !DILocalVariable(name: "istd", scope: !140, file: !3, line: 109, type: !182)
!182 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "psa_ingress_input_metadata_t", file: !47, line: 45, size: 192, align: 32, elements: !183)
!183 = !{!184, !186, !188, !190}
!184 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_port", scope: !182, file: !47, line: 48, baseType: !185, size: 32)
!185 = !DIDerivedType(tag: DW_TAG_typedef, name: "PortId_t", file: !47, line: 6, baseType: !83)
!186 = !DIDerivedType(tag: DW_TAG_member, name: "packet_path", scope: !182, file: !47, line: 49, baseType: !187, size: 8, offset: 32)
!187 = !DIDerivedType(tag: DW_TAG_typedef, name: "PSA_PacketPath_t", file: !47, line: 14, baseType: !50)
!188 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_timestamp", scope: !182, file: !47, line: 50, baseType: !189, size: 64, offset: 64)
!189 = !DIDerivedType(tag: DW_TAG_typedef, name: "Timestamp_t", file: !47, line: 7, baseType: !24)
!190 = !DIDerivedType(tag: DW_TAG_member, name: "parser_error", scope: !182, file: !47, line: 51, baseType: !49, size: 8, offset: 128)
!191 = !DILocalVariable(name: "ostd", scope: !140, file: !3, line: 115, type: !192)
!192 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "psa_ingress_output_metadata_t", file: !47, line: 54, size: 128, align: 32, elements: !193)
!193 = !{!194, !196, !197, !199, !201, !203, !204}
!194 = !DIDerivedType(tag: DW_TAG_member, name: "multicast_group", scope: !192, file: !47, line: 57, baseType: !195, size: 32)
!195 = !DIDerivedType(tag: DW_TAG_typedef, name: "MulticastGroup_t", file: !47, line: 10, baseType: !83)
!196 = !DIDerivedType(tag: DW_TAG_member, name: "egress_port", scope: !192, file: !47, line: 58, baseType: !185, size: 32, offset: 32)
!197 = !DIDerivedType(tag: DW_TAG_member, name: "class_of_service", scope: !192, file: !47, line: 59, baseType: !198, size: 8, offset: 64)
!198 = !DIDerivedType(tag: DW_TAG_typedef, name: "ClassOfService_t", file: !47, line: 8, baseType: !50)
!199 = !DIDerivedType(tag: DW_TAG_member, name: "clone", scope: !192, file: !47, line: 60, baseType: !200, size: 8, offset: 72)
!200 = !DIBasicType(name: "_Bool", size: 8, encoding: DW_ATE_boolean)
!201 = !DIDerivedType(tag: DW_TAG_member, name: "clone_session_id", scope: !192, file: !47, line: 61, baseType: !202, size: 16, offset: 80)
!202 = !DIDerivedType(tag: DW_TAG_typedef, name: "CloneSessionId_t", file: !47, line: 9, baseType: !29)
!203 = !DIDerivedType(tag: DW_TAG_member, name: "drop", scope: !192, file: !47, line: 62, baseType: !200, size: 8, offset: 96)
!204 = !DIDerivedType(tag: DW_TAG_member, name: "resubmit", scope: !192, file: !47, line: 63, baseType: !200, size: 8, offset: 104)
!205 = !DILocalVariable(name: "hit_1", scope: !206, file: !3, line: 149, type: !22)
!206 = distinct !DILexicalBlock(scope: !140, file: !3, line: 148, column: 9)
!207 = !DILocalVariable(name: "meta_1", scope: !206, file: !3, line: 150, type: !192)
!208 = !DILocalVariable(name: "key", scope: !209, file: !3, line: 154, type: !211)
!209 = distinct !DILexicalBlock(scope: !210, file: !3, line: 152, column: 9)
!210 = distinct !DILexicalBlock(scope: !206, file: !3, line: 151, column: 5)
!211 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ingress_tbl_fwd_key", file: !3, line: 47, size: 32, align: 32, elements: !212)
!212 = !{!213}
!213 = !DIDerivedType(tag: DW_TAG_member, name: "field0", scope: !211, file: !3, line: 48, baseType: !112, size: 32)
!214 = !DILocalVariable(name: "value", scope: !209, file: !3, line: 157, type: !215)
!215 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !114, size: 64)
!216 = !DILocalVariable(name: "____fmt", scope: !217, file: !3, line: 201, type: !221)
!217 = distinct !DILexicalBlock(scope: !218, file: !3, line: 201, column: 17)
!218 = distinct !DILexicalBlock(scope: !219, file: !3, line: 200, column: 29)
!219 = distinct !DILexicalBlock(scope: !220, file: !3, line: 200, column: 17)
!220 = distinct !DILexicalBlock(scope: !140, file: !3, line: 195, column: 9)
!221 = !DICompositeType(tag: DW_TAG_array_type, baseType: !31, size: 584, elements: !222)
!222 = !{!223}
!223 = !DISubrange(count: 73)
!224 = !DILocalVariable(name: "____fmt", scope: !225, file: !3, line: 207, type: !221)
!225 = distinct !DILexicalBlock(scope: !226, file: !3, line: 207, column: 17)
!226 = distinct !DILexicalBlock(scope: !227, file: !3, line: 206, column: 32)
!227 = distinct !DILexicalBlock(scope: !220, file: !3, line: 206, column: 17)
!228 = !DILocalVariable(name: "outHeaderLength", scope: !220, file: !3, line: 209, type: !97)
!229 = !DILocalVariable(name: "outHeaderOffset", scope: !220, file: !3, line: 214, type: !97)
!230 = !DILocalVariable(name: "returnCode", scope: !231, file: !3, line: 216, type: !97)
!231 = distinct !DILexicalBlock(scope: !232, file: !3, line: 215, column: 39)
!232 = distinct !DILexicalBlock(scope: !220, file: !3, line: 215, column: 17)
!233 = !DILocalVariable(name: "____fmt", scope: !234, file: !3, line: 271, type: !237)
!234 = distinct !DILexicalBlock(scope: !235, file: !3, line: 271, column: 13)
!235 = distinct !DILexicalBlock(scope: !236, file: !3, line: 270, column: 40)
!236 = distinct !DILexicalBlock(scope: !140, file: !3, line: 270, column: 13)
!237 = !DICompositeType(tag: DW_TAG_array_type, baseType: !31, size: 592, elements: !238)
!238 = !{!239}
!239 = !DISubrange(count: 74)
!240 = !DILocation(line: 93, column: 29, scope: !140)
!241 = !DILocation(line: 90, column: 37, scope: !140)
!242 = !DILocation(line: 93, column: 5, scope: !140)
!243 = !DILocation(line: 102, column: 14, scope: !140)
!244 = !DILocation(line: 102, column: 51, scope: !140)
!245 = !DILocation(line: 103, column: 19, scope: !140)
!246 = !DILocation(line: 104, column: 36, scope: !140)
!247 = !{!248, !131, i64 0}
!248 = !{!"xdp_md", !131, i64 0, !131, i64 4, !131, i64 8, !131, i64 12, !131, i64 16}
!249 = !DILocation(line: 104, column: 25, scope: !140)
!250 = !DILocation(line: 104, column: 18, scope: !140)
!251 = !DILocation(line: 104, column: 11, scope: !140)
!252 = !DILocation(line: 105, column: 47, scope: !140)
!253 = !{!248, !131, i64 4}
!254 = !DILocation(line: 105, column: 36, scope: !140)
!255 = !DILocation(line: 105, column: 29, scope: !140)
!256 = !DILocation(line: 105, column: 11, scope: !140)
!257 = !DILocation(line: 106, column: 5, scope: !140)
!258 = !DILocation(line: 106, column: 9, scope: !140)
!259 = !DILocation(line: 110, column: 30, scope: !140)
!260 = !{!248, !131, i64 12}
!261 = !DILocation(line: 109, column: 41, scope: !140)
!262 = !DILocation(line: 111, column: 30, scope: !140)
!263 = !DILocation(line: 115, column: 42, scope: !140)
!264 = !DILocation(line: 121, column: 34, scope: !265)
!265 = distinct !DILexicalBlock(scope: !266, file: !3, line: 121, column: 13)
!266 = distinct !DILexicalBlock(scope: !140, file: !3, line: 119, column: 12)
!267 = !DILocation(line: 121, column: 28, scope: !265)
!268 = !DILocation(line: 121, column: 13, scope: !266)
!269 = !DILocation(line: 126, column: 46, scope: !266)
!270 = !{!271, !271, i64 0}
!271 = !{!"long long", !132, i64 0}
!272 = !DILocation(line: 126, column: 94, scope: !266)
!273 = !DILocation(line: 126, column: 37, scope: !266)
!274 = !{!275, !271, i64 0}
!275 = !{!"headers", !276, i64 0, !278, i64 24}
!276 = !{!"ethernet_t", !271, i64 0, !271, i64 8, !277, i64 16, !132, i64 18}
!277 = !{!"short", !132, i64 0}
!278 = !{!"ipv4_t", !132, i64 0, !132, i64 1, !132, i64 2, !277, i64 4, !277, i64 6, !132, i64 8, !277, i64 10, !132, i64 12, !132, i64 13, !277, i64 14, !131, i64 16, !131, i64 20, !132, i64 24}
!279 = !DILocation(line: 129, column: 46, scope: !266)
!280 = !DILocation(line: 129, column: 94, scope: !266)
!281 = !DILocation(line: 129, column: 37, scope: !266)
!282 = !{!275, !271, i64 8}
!283 = !DILocation(line: 132, column: 48, scope: !266)
!284 = !{!277, !277, i64 0}
!285 = !DILocation(line: 132, column: 39, scope: !266)
!286 = !{!275, !277, i64 16}
!287 = !DILocation(line: 135, column: 40, scope: !266)
!288 = !{!275, !132, i64 18}
!289 = !DILocation(line: 137, column: 9, scope: !266)
!290 = !DILocation(line: 154, column: 13, scope: !209)
!291 = !DILocation(line: 155, column: 17, scope: !209)
!292 = !DILocation(line: 155, column: 24, scope: !209)
!293 = !{!294, !131, i64 0}
!294 = !{!"ingress_tbl_fwd_key", !131, i64 0}
!295 = !DILocation(line: 157, column: 43, scope: !209)
!296 = !DILocation(line: 159, column: 21, scope: !209)
!297 = !DILocation(line: 160, column: 23, scope: !298)
!298 = distinct !DILexicalBlock(scope: !209, file: !3, line: 160, column: 17)
!299 = !DILocation(line: 160, column: 17, scope: !209)
!300 = !DILocation(line: 149, column: 8, scope: !206)
!301 = !DILocation(line: 163, column: 25, scope: !302)
!302 = distinct !DILexicalBlock(scope: !298, file: !3, line: 160, column: 32)
!303 = !DILocation(line: 167, column: 23, scope: !304)
!304 = distinct !DILexicalBlock(scope: !209, file: !3, line: 167, column: 17)
!305 = !DILocation(line: 167, column: 17, scope: !209)
!306 = !DILocation(line: 169, column: 32, scope: !307)
!307 = distinct !DILexicalBlock(scope: !304, file: !3, line: 167, column: 32)
!308 = !{!309, !131, i64 0}
!309 = !{!"ingress_tbl_fwd_value", !131, i64 0, !132, i64 4}
!310 = !DILocation(line: 169, column: 17, scope: !307)
!311 = !DILocation(line: 191, column: 17, scope: !210)
!312 = !DILocation(line: 150, column: 42, scope: !206)
!313 = !DILocation(line: 176, column: 61, scope: !314)
!314 = distinct !DILexicalBlock(scope: !315, file: !3, line: 172, column: 1)
!315 = distinct !DILexicalBlock(scope: !316, file: !3, line: 171, column: 25)
!316 = distinct !DILexicalBlock(scope: !307, file: !3, line: 169, column: 40)
!317 = !DILocation(line: 176, column: 82, scope: !314)
!318 = !{!132, !132, i64 0}
!319 = !DILocation(line: 209, column: 17, scope: !220)
!320 = !DILocation(line: 210, column: 37, scope: !321)
!321 = distinct !DILexicalBlock(scope: !220, file: !3, line: 210, column: 17)
!322 = !DILocation(line: 210, column: 17, scope: !321)
!323 = !DILocation(line: 210, column: 17, scope: !220)
!324 = !DILocation(line: 214, column: 58, scope: !220)
!325 = !DILocation(line: 214, column: 17, scope: !220)
!326 = !DILocation(line: 215, column: 33, scope: !232)
!327 = !DILocation(line: 215, column: 17, scope: !220)
!328 = !DILocation(line: 216, column: 21, scope: !231)
!329 = !DILocation(line: 217, column: 30, scope: !231)
!330 = !DILocation(line: 218, column: 21, scope: !331)
!331 = distinct !DILexicalBlock(scope: !231, file: !3, line: 218, column: 21)
!332 = !DILocation(line: 222, column: 38, scope: !220)
!333 = !DILocation(line: 222, column: 27, scope: !220)
!334 = !DILocation(line: 222, column: 20, scope: !220)
!335 = !DILocation(line: 223, column: 49, scope: !220)
!336 = !DILocation(line: 225, column: 37, scope: !337)
!337 = distinct !DILexicalBlock(scope: !220, file: !3, line: 225, column: 17)
!338 = !DILocation(line: 225, column: 17, scope: !337)
!339 = !DILocation(line: 225, column: 17, scope: !220)
!340 = !DILocation(line: 223, column: 38, scope: !220)
!341 = !DILocation(line: 223, column: 31, scope: !220)
!342 = !DILocation(line: 226, column: 42, scope: !343)
!343 = distinct !DILexicalBlock(scope: !344, file: !3, line: 226, column: 21)
!344 = distinct !DILexicalBlock(scope: !337, file: !3, line: 225, column: 49)
!345 = !DILocation(line: 226, column: 36, scope: !343)
!346 = !DILocation(line: 226, column: 21, scope: !344)
!347 = !DILocation(line: 230, column: 47, scope: !344)
!348 = !DILocation(line: 230, column: 45, scope: !344)
!349 = !DILocation(line: 231, column: 29, scope: !344)
!350 = !DILocation(line: 107, column: 19, scope: !140)
!351 = !DILocation(line: 232, column: 17, scope: !352)
!352 = distinct !DILexicalBlock(scope: !344, file: !3, line: 232, column: 17)
!353 = !DILocation(line: 233, column: 29, scope: !344)
!354 = !DILocation(line: 234, column: 17, scope: !355)
!355 = distinct !DILexicalBlock(scope: !344, file: !3, line: 234, column: 17)
!356 = !DILocation(line: 235, column: 29, scope: !344)
!357 = !DILocation(line: 236, column: 17, scope: !358)
!358 = distinct !DILexicalBlock(scope: !344, file: !3, line: 236, column: 17)
!359 = !DILocation(line: 237, column: 29, scope: !344)
!360 = !DILocation(line: 238, column: 17, scope: !361)
!361 = distinct !DILexicalBlock(scope: !344, file: !3, line: 238, column: 17)
!362 = !DILocation(line: 239, column: 29, scope: !344)
!363 = !DILocation(line: 240, column: 17, scope: !364)
!364 = distinct !DILexicalBlock(scope: !344, file: !3, line: 240, column: 17)
!365 = !DILocation(line: 241, column: 29, scope: !344)
!366 = !DILocation(line: 242, column: 17, scope: !367)
!367 = distinct !DILexicalBlock(scope: !344, file: !3, line: 242, column: 17)
!368 = !DILocation(line: 245, column: 47, scope: !344)
!369 = !DILocation(line: 245, column: 45, scope: !344)
!370 = !DILocation(line: 246, column: 29, scope: !344)
!371 = !DILocation(line: 247, column: 17, scope: !372)
!372 = distinct !DILexicalBlock(scope: !344, file: !3, line: 247, column: 17)
!373 = !DILocation(line: 248, column: 29, scope: !344)
!374 = !DILocation(line: 249, column: 17, scope: !375)
!375 = distinct !DILexicalBlock(scope: !344, file: !3, line: 249, column: 17)
!376 = !DILocation(line: 250, column: 29, scope: !344)
!377 = !DILocation(line: 251, column: 17, scope: !378)
!378 = distinct !DILexicalBlock(scope: !344, file: !3, line: 251, column: 17)
!379 = !DILocation(line: 252, column: 29, scope: !344)
!380 = !DILocation(line: 253, column: 17, scope: !381)
!381 = distinct !DILexicalBlock(scope: !344, file: !3, line: 253, column: 17)
!382 = !DILocation(line: 254, column: 29, scope: !344)
!383 = !DILocation(line: 255, column: 17, scope: !384)
!384 = distinct !DILexicalBlock(scope: !344, file: !3, line: 255, column: 17)
!385 = !DILocation(line: 256, column: 29, scope: !344)
!386 = !DILocation(line: 257, column: 17, scope: !387)
!387 = distinct !DILexicalBlock(scope: !344, file: !3, line: 257, column: 17)
!388 = !DILocation(line: 260, column: 49, scope: !344)
!389 = !DILocation(line: 260, column: 47, scope: !344)
!390 = !DILocation(line: 261, column: 29, scope: !344)
!391 = !DILocation(line: 262, column: 17, scope: !392)
!392 = distinct !DILexicalBlock(scope: !344, file: !3, line: 262, column: 17)
!393 = !DILocation(line: 263, column: 29, scope: !344)
!394 = !DILocation(line: 264, column: 17, scope: !395)
!395 = distinct !DILexicalBlock(scope: !344, file: !3, line: 264, column: 17)
!396 = !DILocation(line: 267, column: 13, scope: !344)
!397 = !DILocation(line: 273, column: 16, scope: !140)
!398 = !DILocation(line: 273, column: 9, scope: !140)
!399 = !DILocation(line: 0, scope: !140)
!400 = !DILocation(line: 274, column: 1, scope: !140)
!401 = distinct !DISubprogram(name: "xdp_egress_func", scope: !3, file: !3, line: 277, type: !141, scopeLine: 277, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !402)
!402 = !{!403, !404, !405, !406, !407, !408, !409, !410, !411, !421, !427, !428, !430, !432, !433, !436}
!403 = !DILocalVariable(name: "skb", arg: 1, scope: !401, file: !3, line: 277, type: !89)
!404 = !DILocalVariable(name: "ebpf_packetOffsetInBits", scope: !401, file: !3, line: 278, type: !7)
!405 = !DILocalVariable(name: "ebpf_packetOffsetInBits_save", scope: !401, file: !3, line: 278, type: !7)
!406 = !DILocalVariable(name: "ebpf_errorCode", scope: !401, file: !3, line: 279, type: !49)
!407 = !DILocalVariable(name: "pkt", scope: !401, file: !3, line: 280, type: !15)
!408 = !DILocalVariable(name: "ebpf_packetEnd", scope: !401, file: !3, line: 281, type: !15)
!409 = !DILocalVariable(name: "ebpf_zero", scope: !401, file: !3, line: 282, type: !112)
!410 = !DILocalVariable(name: "ebpf_byte", scope: !401, file: !3, line: 283, type: !23)
!411 = !DILocalVariable(name: "istd", scope: !401, file: !3, line: 285, type: !412)
!412 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "psa_egress_input_metadata_t", file: !47, line: 75, size: 256, align: 32, elements: !413)
!413 = !{!414, !415, !416, !417, !419, !420}
!414 = !DIDerivedType(tag: DW_TAG_member, name: "class_of_service", scope: !412, file: !47, line: 76, baseType: !198, size: 8)
!415 = !DIDerivedType(tag: DW_TAG_member, name: "egress_port", scope: !412, file: !47, line: 77, baseType: !185, size: 32, offset: 32)
!416 = !DIDerivedType(tag: DW_TAG_member, name: "packet_path", scope: !412, file: !47, line: 78, baseType: !187, size: 8, offset: 64)
!417 = !DIDerivedType(tag: DW_TAG_member, name: "instance", scope: !412, file: !47, line: 79, baseType: !418, size: 16, offset: 80)
!418 = !DIDerivedType(tag: DW_TAG_typedef, name: "EgressInstance_t", file: !47, line: 11, baseType: !29)
!419 = !DIDerivedType(tag: DW_TAG_member, name: "egress_timestamp", scope: !412, file: !47, line: 81, baseType: !189, size: 64, offset: 128)
!420 = !DIDerivedType(tag: DW_TAG_member, name: "parser_error", scope: !412, file: !47, line: 82, baseType: !49, size: 8, offset: 192)
!421 = !DILocalVariable(name: "ostd", scope: !401, file: !3, line: 290, type: !422)
!422 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "psa_egress_output_metadata_t", file: !47, line: 85, size: 64, align: 32, elements: !423)
!423 = !{!424, !425, !426}
!424 = !DIDerivedType(tag: DW_TAG_member, name: "clone", scope: !422, file: !47, line: 88, baseType: !200, size: 8)
!425 = !DIDerivedType(tag: DW_TAG_member, name: "clone_session_id", scope: !422, file: !47, line: 89, baseType: !202, size: 16, offset: 16)
!426 = !DIDerivedType(tag: DW_TAG_member, name: "drop", scope: !422, file: !47, line: 90, baseType: !200, size: 8, offset: 32)
!427 = !DILocalVariable(name: "parsed_hdr", scope: !401, file: !3, line: 295, type: !148)
!428 = !DILocalVariable(name: "hit_2", scope: !429, file: !3, line: 317, type: !22)
!429 = distinct !DILexicalBlock(scope: !401, file: !3, line: 316, column: 5)
!430 = !DILocalVariable(name: "outHeaderLength", scope: !431, file: !3, line: 324, type: !97)
!431 = distinct !DILexicalBlock(scope: !401, file: !3, line: 321, column: 5)
!432 = !DILocalVariable(name: "outHeaderOffset", scope: !431, file: !3, line: 326, type: !97)
!433 = !DILocalVariable(name: "returnCode", scope: !434, file: !3, line: 328, type: !97)
!434 = distinct !DILexicalBlock(scope: !435, file: !3, line: 327, column: 35)
!435 = distinct !DILexicalBlock(scope: !431, file: !3, line: 327, column: 13)
!436 = !DILocalVariable(name: "____fmt", scope: !437, file: !3, line: 340, type: !440)
!437 = distinct !DILexicalBlock(scope: !438, file: !3, line: 340, column: 9)
!438 = distinct !DILexicalBlock(scope: !439, file: !3, line: 339, column: 21)
!439 = distinct !DILexicalBlock(scope: !401, file: !3, line: 339, column: 9)
!440 = !DICompositeType(tag: DW_TAG_array_type, baseType: !31, size: 576, elements: !441)
!441 = !{!442}
!442 = !DISubrange(count: 72)
!443 = !DILocation(line: 277, column: 36, scope: !401)
!444 = !DILocation(line: 278, column: 14, scope: !401)
!445 = !DILocation(line: 278, column: 51, scope: !401)
!446 = !DILocation(line: 279, column: 19, scope: !401)
!447 = !DILocation(line: 282, column: 9, scope: !401)
!448 = !DILocation(line: 285, column: 40, scope: !401)
!449 = !DILocation(line: 287, column: 29, scope: !401)
!450 = !DILocation(line: 290, column: 41, scope: !401)
!451 = !DILocation(line: 295, column: 5, scope: !401)
!452 = !DILocation(line: 295, column: 29, scope: !401)
!453 = !DILocation(line: 349, column: 1, scope: !401)
!454 = distinct !DISubprogram(name: "xdp_redirect_dummy", scope: !3, file: !3, line: 352, type: !141, scopeLine: 352, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !455)
!455 = !{!456}
!456 = !DILocalVariable(name: "skb", arg: 1, scope: !454, file: !3, line: 352, type: !89)
!457 = !DILocation(line: 352, column: 39, scope: !454)
!458 = !DILocation(line: 353, column: 5, scope: !454)
