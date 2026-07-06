import os
import unittest


class GuiSmokeTests(unittest.TestCase):
    def test_main_window_constructs_offscreen(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication

        from obscuraprimus.gui_main import MainWindow

        app = QApplication.instance() or QApplication([])
        window = MainWindow()
        try:
            self.assertEqual(window.windowTitle(), "ObscuraPrimus")
            self.assertGreaterEqual(window.centralWidget().count(), 6)
        finally:
            window.close()
            app.processEvents()


if __name__ == "__main__":
    unittest.main()
