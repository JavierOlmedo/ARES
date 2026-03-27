from modules.nmap_scan import NmapModule
from modules.fuzzing import FuzzingModule
from modules.bruteforce import BruteForceModule
from modules.nuclei import NucleiModule

MODULE_REGISTRY = {
    "nmap": NmapModule,
    "fuzzing": FuzzingModule,
    "bruteforce": BruteForceModule,
    "nuclei": NucleiModule,
}
