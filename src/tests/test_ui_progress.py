import unittest

from src.ui.app import SDKKitApp


class TestScanStageProgress(unittest.TestCase):
    def test_scan_stage_tracking_does_not_schedule_eta_timer(self):
        app = SDKKitApp.__new__(SDKKitApp)
        app._active_scan_stage = ""
        app._scan_stage_started_at = 0.0
        app._scan_stage_durations = {}
        app._step_title = ""

        def set_step(title: str) -> None:
            app._step_title = title

        app._set_step = set_step

        app._scan_stage_begin("gobjects", "Step 1/3: GObjects")

        self.assertEqual(app._active_scan_stage, "gobjects")
        self.assertEqual(app._step_title, "Step 1/3: GObjects")
        self.assertFalse(hasattr(app, "_scan_eta_job"))

        app._scan_stage_finish("gobjects")

        self.assertEqual(app._active_scan_stage, "")
        self.assertIn("gobjects", app._scan_stage_durations)


if __name__ == "__main__":
    unittest.main()
