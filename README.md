# FGW-Scripts
- Uses zone names as the ‎`source` / ‎`target` in the CSV (falling back to interface name if not in a zone).
- Produces a CSV ready for draw.io CSV import.

In draw.io, you then import ‎⁠fortigate_edges_zones.csv⁠ via Arrange → Insert → Advanced → CSV… and map:

- ‎⁠linkSource⁠ → ‎⁠source⁠
- ‎⁠linkTarget⁠ → ‎⁠target⁠
- ‎⁠linkLabel⁠ → ‎⁠label⁠

This will give you one node per zone (or interface if it’s not in a zone) with arrows reflecting allowed flows between them.
