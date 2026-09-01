"""Offline checks for read-only inventory/uItemDraw snapshot field decoding."""
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("gui_snapshot", Path(__file__).with_name("snapshot-rerev2-gui-controllers.py"))
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


class Tests(unittest.TestCase):
    def test_campaign_vtable_not_old_enum_label(self):
        self.assertEqual(snapshot.CONTROLLERS["uGUIInventoryCampaign"], 0x139CCC8)

    def test_native_item_draw_fields_use_their_own_offsets(self):
        data = bytearray(0x108)
        for offset, value in ((0, 0x13BF4D0), (0x80, 2), (0x84, 6), (0x88, 6),
                              (0x8C, 1), (0x94, 123), (0x9C, 456), (0xE0, 0x3000), (0x100, 0x4000)):
            struct.pack_into("<I", data, offset, value)
        struct.pack_into("<4i", data, 0xA4, 900, 189, 1470, 510)
        data[0x90] = 1
        memory = {(0x1000 + 0x2CC, 4): struct.pack("<I", 0x2000), (0x2000, 0x108): bytes(data)}
        with patch.object(snapshot, "read_memory", side_effect=lambda _k, _p, address, size: memory[(address, size)]):
            row = snapshot.item_preview_fields(None, None, 0x1000)
        self.assertTrue(row["verifiedItemDraw"])
        self.assertEqual(row["destinationRectangle"], (900, 189, 1470, 510))
        self.assertEqual(row["destinationSize"], [570, 321])
        self.assertEqual(row["drawView"], 1)
        self.assertEqual(row["requestedScreenView"], 6)
        self.assertEqual(row["activeScreenView"], 6)
        self.assertTrue(row["overlay"])
        self.assertEqual(row["camera"], "0x00003000")
        self.assertEqual(row["requestedItem"], 456)

    def test_absent_link_or_object_is_not_read_as_a_model(self):
        for link in (None, bytes(4)):
            with patch.object(snapshot, "read_memory", return_value=link) as reader:
                row = snapshot.item_preview_fields(None, None, 0x1000)
            self.assertFalse(row["verifiedItemDraw"])
            self.assertEqual(reader.call_count, 1)

    def test_wrong_vtable_is_not_interpreted(self):
        with patch.object(snapshot, "read_memory", side_effect=(struct.pack("<I", 0x2000), bytes(0x108))):
            row = snapshot.item_preview_fields(None, None, 0x1000)
        self.assertFalse(row["verifiedItemDraw"])
        self.assertNotIn("destinationRectangle", row)


if __name__ == "__main__":
    unittest.main()
