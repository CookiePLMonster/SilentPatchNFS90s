# SilentPatch for NFS2: Special Edition, NFS3: Hot Pursuit NFS4: High Stakes and NFS: Porsche Unleashed

This modification addresses several numerous more or less several bugs in the classic Need for Speed games from the late 90s - starting from Need for Speed 2: Special Edition,
through Need for Speed: Porsche Unleashed. Since all those games already have their established unofficial patches, I concentrated my efforts on issues either omitted by those patches,
or (in the case of NFS2SE and NFS Porsche) caused by them.

**Modern Patches from VEG ([NFS3](https://veg.by/en/projects/nfs3/)/[NFS4](https://veg.by/en/projects/nfs4/))**
**and Verok ([NFS2SE](https://community.pcgamingwiki.com/files/file/2448-need-for-speed-ii-second-edition-patch-by-verok-verokster-105/)/[NFS Porsche](https://community.pcgamingwiki.com/files/file/2708-veroks-verokster-need-for-speed-v-porsche-unleashed-patch-v106/))**
**are strongly recommended, although not mandatory. SilentPatch can work with or without them.**

## Featured fixes
Fixes marked with ⚙️ can be configured/toggled via the INI file.

### Essential fixes:
* ⚙️ Locked all (NFS3/NFS Porsche) or specific problematic threads (NFS2SE/NFS4) to one core, while allowing worker threads to use any CPU cores - combining good stability and performance. This option has to be enabled by adding `SingleProcAffinity=1` to an INI file named like the game's executable. This change is fully compatible with Modern Patches and overrides its single-core affinity solution.
* (NFS2SE) Fixed a potential race condition on starting the movie decoding thread.
* (NFS2SE) Fixed a bug preventing controller button mappings from working correctly with gamepads that report more than 15 buttons (such as the Xbox One controller).
* (NFS2SE) Fixed the game closing when the controller disconnects during the race.
* (NFS2SE, Verok's Modern Patch only) Fixed an issue where online races were displayed only on the top half of the screen as if they were split-screen races.
* (NFS Porsche) Fixed a startup crash due to DirectInput controller enumeration being broken under specific circumstances on Windows 10 and newer.
* (NFS Porsche) Fixed severe performance issues on Windows 10 and newer when rebinding controls.
* (NFS Porsche, Verok's Modern Patch only) Fixed unresponsive keyboard inputs after <kbd>Alt</kbd> + <kbd>Tab</kbd> during the race.
* (NFS Porsche, Verok's Modern Patch only) Fixed a severe memory leak in OpenGL1 and OpenGL3 thrash drivers occurring after every race.

### Miscellaneous fixes:
* <kbd>Alt</kbd> + <kbd>F4</kbd> now works.
* <kbd>Num Lock</kbd>, <kbd>Caps Lock</kbd>, and <kbd>Scroll Lock</kbd> don't get forcibly disabled on game launch anymore.
* (NFS2SE/NFS3/NFS4) Fixed issues with stuttery/unresponsive mouse cursor in menus when using mice with high polling rates.
* (NFS2SE/NFS3/NFS4) Fixed a controller polling bug resulting in potential incompatibilities with DirectInput wrappers such as Xidi.

### Enhancements:
* Pasting text into text boxes now works with <kbd>Ctrl</kbd> + <kbd>V</kbd>.

## Compilation requirements
* [Premake5](https://premake.github.io/) and Visual Studio 2022 are required for project generation and compilation.
  Invoke `premake5 vs2022` in the main project directory to generate a project.
