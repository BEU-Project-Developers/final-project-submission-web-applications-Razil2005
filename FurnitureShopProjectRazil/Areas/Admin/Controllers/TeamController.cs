using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Hosting;
using FurnitureShopProjectRazil.Models;
using System.IO;
using System.Threading.Tasks;
using FurnitureShopProjectRazil.Data;
using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc.Rendering; // SelectList üçün

namespace FurnitureShopProjectRazil.Areas.Admin.Controllers
{
    [Area("Admin")]
    // [Authorize(Roles = "Admin")]
    public class TeamController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _env;

        public TeamController(AppDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }

        // INDEX
        public async Task<IActionResult> Index()
        {
            var teams = await _context.Teams
                                .Include(t => t.Profession) // Profession məlumatlarını yüklə
                                .OrderByDescending(t => t.Id)
                                .ToListAsync();
            return View(teams);
        }

        // CREATE - GET
        [HttpGet]
        public async Task<IActionResult> Create()
        {
            // Profession-ları dropdown üçün View-a göndər
            ViewBag.Professions = new SelectList(await _context.Professions.OrderBy(p => p.Name).ToListAsync(), "Id", "Name");
            return View();
        }

        // CREATE - POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Team team)
        {
            if (ModelState.IsValid)
            {
                if (team.Photo != null && team.Photo.Length > 0)
                {
                    string folderPath = Path.Combine(_env.WebRootPath, "uploads", "team_images");
                    if (!Directory.Exists(folderPath))
                    {
                        Directory.CreateDirectory(folderPath);
                    }
                    string fileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(team.Photo.FileName);
                    string filePath = Path.Combine(folderPath, fileName);

                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await team.Photo.CopyToAsync(stream);
                    }
                    team.ImagePath = $"/uploads/team_images/{fileName}";
                }
                else
                {
                    // Əgər şəkil məcburi deyilsə və yüklənməyibsə, ImagePath null və ya boş olacaq
                    team.ImagePath = null;
                }

                await _context.Teams.AddAsync(team);
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "Komanda üzvü uğurla yaradıldı.";
                return RedirectToAction(nameof(Index));
            }

            // ModelState valid deyilsə, Profession-ları yenidən yüklə
            ViewBag.Professions = new SelectList(await _context.Professions.OrderBy(p => p.Name).ToListAsync(), "Id", "Name", team.ProfessionId);
            return View(team);
        }

        // UPDATE - GET
        [HttpGet]
        public async Task<IActionResult> Update(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var team = await _context.Teams.FindAsync(id);
            if (team == null)
            {
                return NotFound();
            }

            ViewBag.Professions = new SelectList(await _context.Professions.OrderBy(p => p.Name).ToListAsync(), "Id", "Name", team.ProfessionId);
            return View(team);
        }

        // UPDATE - POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Update(int id, Team team)
        {
            if (id != team.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                var existingTeam = await _context.Teams.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id);
                if (existingTeam == null) return NotFound();

                if (team.Photo != null && team.Photo.Length > 0)
                {
                    // Köhnə şəkili sil
                    if (!string.IsNullOrEmpty(existingTeam.ImagePath))
                    {
                        string oldImagePathFull = Path.Combine(_env.WebRootPath, existingTeam.ImagePath.TrimStart('/'));
                        if (System.IO.File.Exists(oldImagePathFull))
                        {
                            System.IO.File.Delete(oldImagePathFull);
                        }
                    }

                    // Yeni şəkili yüklə
                    string folderPath = Path.Combine(_env.WebRootPath, "uploads", "team_images");
                    if (!Directory.Exists(folderPath)) Directory.CreateDirectory(folderPath);
                    string fileName = Guid.NewGuid().ToString() + "_" + Path.GetFileName(team.Photo.FileName);
                    string filePath = Path.Combine(folderPath, fileName);
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await team.Photo.CopyToAsync(stream);
                    }
                    team.ImagePath = $"/uploads/team_images/{fileName}";
                }
                else
                {
                    // Yeni şəkil yüklənməyibsə, köhnə ImagePath-i qoru
                    team.ImagePath = existingTeam.ImagePath;
                }

                try
                {
                    _context.Update(team);
                    await _context.SaveChangesAsync();
                    TempData["SuccessMessage"] = "Komanda üzvü uğurla yeniləndi.";
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TeamExists(team.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }

            ViewBag.Professions = new SelectList(await _context.Professions.OrderBy(p => p.Name).ToListAsync(), "Id", "Name", team.ProfessionId);
            return View(team);
        }

        // DELETE - GET
        [HttpGet]
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var team = await _context.Teams
                .Include(t => t.Profession)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (team == null)
            {
                return NotFound();
            }

            return View(team);
        }

        // DELETE - POST
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var team = await _context.Teams.FindAsync(id);
            if (team == null)
            {
                TempData["ErrorMessage"] = "Komanda üzvü tapılmadı.";
                return RedirectToAction(nameof(Index));
            }

            // Şəkili serverdən sil
            if (!string.IsNullOrEmpty(team.ImagePath))
            {
                string imagePathFull = Path.Combine(_env.WebRootPath, team.ImagePath.TrimStart('/'));
                if (System.IO.File.Exists(imagePathFull))
                {
                    System.IO.File.Delete(imagePathFull);
                }
            }

            _context.Teams.Remove(team);
            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = "Komanda üzvü uğurla silindi.";
            return RedirectToAction(nameof(Index));
        }

        private bool TeamExists(int id)
        {
            return _context.Teams.Any(e => e.Id == id);
        }
    }
}