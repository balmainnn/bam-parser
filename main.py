import logging
from pathlib import Path
from ui.app import BAMParserApp
if __name__ == "__main__":
    logging.basicConfig(filename=Path(__file__).with_name("bam_parser.log"), level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", encoding="utf-8")
    BAMParserApp().mainloop()
