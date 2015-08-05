object MainForm: TMainForm
  Left = 282
  Top = 145
  Width = 385
  Height = 212
  Caption = 'aPLib - Borland C++Builder Demo'
  Color = clBtnFace
  Constraints.MinHeight = 212
  Constraints.MinWidth = 385
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 377
    Height = 185
    Align = alClient
    BevelOuter = bvLowered
    TabOrder = 0
    DesignSize = (
      377
      185)
    object LabelaPLib2: TLabel
      Left = 207
      Top = 8
      Width = 97
      Height = 38
      Anchors = [akTop, akRight]
      Caption = 'aPLib'
      Font.Charset = ANSI_CHARSET
      Font.Color = clGray
      Font.Height = -32
      Font.Name = 'Verdana'
      Font.Style = [fsBold]
      ParentFont = False
      Transparent = True
    end
    object LabelaPLib1: TLabel
      Left = 203
      Top = 4
      Width = 97
      Height = 38
      Anchors = [akTop, akRight]
      Caption = 'aPLib'
      Font.Charset = ANSI_CHARSET
      Font.Color = clWindowText
      Font.Height = -32
      Font.Name = 'Verdana'
      Font.Style = [fsBold]
      ParentFont = False
      Transparent = True
    end
    object Label5: TLabel
      Left = 223
      Top = 48
      Width = 98
      Height = 13
      Anchors = [akTop, akRight]
      Caption = 'the smaller the better'
    end
    object GroupBox1: TGroupBox
      Left = 8
      Top = 80
      Width = 362
      Height = 65
      Anchors = [akLeft, akRight, akBottom]
      Caption = '  Progress  '
      TabOrder = 0
      DesignSize = (
        362
        65)
      object LabelResult: TLabel
        Left = 16
        Top = 40
        Width = 330
        Height = 13
        Alignment = taCenter
        Anchors = [akLeft, akTop, akRight]
        AutoSize = False
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clMaroon
        Font.Height = -11
        Font.Name = 'MS Sans Serif'
        Font.Style = []
        ParentFont = False
      end
      object ProgressBar: TProgressBar
        Left = 15
        Top = 25
        Width = 331
        Height = 9
        Anchors = [akLeft, akTop, akRight]
        Min = 0
        Max = 100
        TabOrder = 0
      end
    end
    object ButtonCancel: TButton
      Left = 295
      Top = 153
      Width = 75
      Height = 25
      Anchors = [akRight, akBottom]
      Caption = 'Cancel'
      Enabled = False
      TabOrder = 1
      OnClick = ButtonCancelClick
    end
    object ButtonCompress: TButton
      Left = 16
      Top = 16
      Width = 75
      Height = 25
      Caption = 'Compress'
      TabOrder = 2
      OnClick = ButtonCompressClick
    end
    object ButtonDecompress: TButton
      Left = 16
      Top = 48
      Width = 75
      Height = 25
      Caption = 'Decompress'
      TabOrder = 3
      OnClick = ButtonDecompressClick
    end
  end
  object OpenDialog: TOpenDialog
    Filter = 'Any File (*.*)|*.*'
    Left = 112
    Top = 24
  end
end
