Add-Type -AssemblyName System.Drawing
$assetRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\assets'))
New-Item -ItemType Directory -Path $assetRoot -Force | Out-Null
Add-Type -AssemblyName System.Drawing
$iconSizes = @(16,24,32,48,64,128,256)
$iconImages = @()
foreach ($iconSize in $iconSizes) {
    $canvas = [System.Drawing.Bitmap]::new($iconSize,$iconSize)
    $gfx = [System.Drawing.Graphics]::FromImage($canvas)
    $gfx.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $gfx.ScaleTransform(($iconSize/256.0),($iconSize/256.0))
    $gfx.Clear([System.Drawing.Color]::Transparent)
    $shape = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $shape.AddArc(12,12,100,100,180,90)
    $shape.AddArc(144,12,100,100,270,90)
    $shape.AddArc(144,144,100,100,0,90)
    $shape.AddArc(12,144,100,100,90,90)
    $shape.CloseFigure()
    $gradient = [System.Drawing.Drawing2D.LinearGradientBrush]::new([System.Drawing.Rectangle]::new(12,12,232,232),[System.Drawing.Color]::FromArgb(245,77,87),[System.Drawing.Color]::FromArgb(191,24,48),90.0)
    $gfx.FillPath($gradient,$shape)
    $vShape = [System.Drawing.PointF[]]@([System.Drawing.PointF]::new(54,73),[System.Drawing.PointF]::new(91,73),[System.Drawing.PointF]::new(128,154),[System.Drawing.PointF]::new(165,73),[System.Drawing.PointF]::new(202,73),[System.Drawing.PointF]::new(146,190),[System.Drawing.PointF]::new(110,190))
    $gfx.FillPolygon([System.Drawing.Brushes]::White,$vShape)
    if ($iconSize -eq 256) { $canvas.Save((Join-Path $assetRoot 'VALO-icon.png'),[System.Drawing.Imaging.ImageFormat]::Png) }
    $pngStream = [System.IO.MemoryStream]::new()
    $canvas.Save($pngStream,[System.Drawing.Imaging.ImageFormat]::Png)
    $iconImages += ,($pngStream.ToArray())
    $pngStream.Dispose(); $gradient.Dispose(); $shape.Dispose(); $gfx.Dispose(); $canvas.Dispose()
}
$icoStream = [System.IO.File]::Create((Join-Path $assetRoot 'VALO.ico'))
$writer = [System.IO.BinaryWriter]::new($icoStream)
$writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$iconSizes.Count)
$offset = 6 + 16*$iconSizes.Count
for ($i=0; $i -lt $iconSizes.Count; $i++) {
    $dimension = if ($iconSizes[$i] -eq 256) {0} else {$iconSizes[$i]}
    $writer.Write([byte]$dimension); $writer.Write([byte]$dimension); $writer.Write([byte]0); $writer.Write([byte]0)
    $writer.Write([uint16]1); $writer.Write([uint16]32); $writer.Write([uint32]$iconImages[$i].Length); $writer.Write([uint32]$offset)
    $offset += $iconImages[$i].Length
}
foreach ($pngData in $iconImages) { $writer.Write([byte[]]$pngData) }
$writer.Dispose(); $icoStream.Dispose()
