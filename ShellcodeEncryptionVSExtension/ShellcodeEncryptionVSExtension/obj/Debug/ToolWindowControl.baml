   M S B A M L   `   `   `  ����"  ShellcodeEncryptionVSExtension6    0ShellcodeEncryptionVSExtension.ToolWindowControl   5      W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5      R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5      Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5      @d2http://schemas.microsoft.com/expression/blend/2008     5      ���#2D2D30
�������.��5
      �   � RowDefinitions  5   
   �� 5      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $
��Auto �6   �� 5      $��* �6   .+�5   
   �� $��0��6   $��Shellcode To Encrypt��5      $
��Bold"�5      
�������$��Center=�5      $��0,10,0,5q�5      �� 5"   
   -   5         ��Name$ ShellcodeTextBox��5#      $��1��5"      $��80��5$      $
��10,5q�5%       �� TextWrapping$
 Wrap=�5&       �� AcceptsReturn . ���#1E1E1E
����������#3F3F46" �� VerticalScrollBarVisibility$
 Auto=�5+       � ToolTip$H BIngresa el shellcode en formato hexadecimal (ej: \x31\xc0\x50\x68)��5,      �� 5/   
   $��2��6   $	��Key��50      $
��Bold"�51      
�������$��Center=�53      $��0,10,0,5q�54      �� 56   
   -   5        $ 
KeyTextBox��57      $��3��56      $��30��58      $
��10,5q�59      ���#1E1E1E
����������#3F3F46$2 ,Ingresa la clave para encriptar el shellcode��5=      �� 5@   
   $��4��6   $��Encryption Method��5A      $
��Bold"�5B      
�������$��Center=�5D      $��0,10,0,5q�5E      �� 5G   
   -   5         ��Name$ EncryptionMethodComboBox��5H      $��5��5G      $
��10,5q�5I      ���#1E1E1E
���   ����#3F3F46.@�5M      �� $	��XOR��6    �� 
IsSelected . 6)   �� 5N      $	��AES��6   5O      �� 5R   
   -   5         ��Name$ EncryptButton��5S      $��6��5R      $��Encrypt��5T      $	��120��5U      $��40��5V      $
��0,10q�5W      $��Center=�5X      ���#FFA500
���   �$
��Bold"�5[      5\      �� 5_   
   $��7��6   $��Plain Text Result��5`      $
��Bold"�5a      
�������$��Center=�5c      $��0,10,0,5q�5d      �� 5g   
   $��9��6   $��
Hex Result��5h      $
��Bold"�5i      
�������$��Center=�5k      $��0,10,0,5q�5l      �� 5n   
   -   5        $ HexResultBox��5o      $��10��5n      $��10,27,10,26q�5p      	 �� 
IsReadOnly	 . $
 Wrap=�5r      ���#1E1E1E
����������#3F3F46$
 Auto=�5v      5x      5y      