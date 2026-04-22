#!/usr/bin/env python3
"""
Main script to generate the revised BAB 1 & BAB 2 for Xpecto Shield thesis.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gen_helpers import setup_doc, add_blank_page
from gen_bab1 import write_bab1
from gen_bab2_p1 import write_bab2_part1
from gen_bab2_p2 import write_bab2_part2


def main():
    doc = setup_doc()

    # BAB 1
    write_bab1(doc)

    # Page break + blank page between BAB 1 and BAB 2
    add_blank_page(doc)

    # BAB 2
    write_bab2_part1(doc)
    write_bab2_part2(doc)

    output_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'Revisi_BAB_1_dan_BAB_2_Xpecto_Shield.docx'
    )
    doc.save(output_path)
    print(f'✅ Dokumen berhasil dibuat: {output_path}')
    print(f'   File size: {os.path.getsize(output_path):,} bytes')


if __name__ == '__main__':
    main()
