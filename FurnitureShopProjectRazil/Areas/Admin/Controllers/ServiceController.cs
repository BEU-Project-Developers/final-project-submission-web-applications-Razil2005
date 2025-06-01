using Microsoft.AspNetCore.Mvc;
using FurnitureShopProjectRazil.Models;
using System.Threading.Tasks;
using FurnitureShopProjectRazil.Data;
using System.Linq;
using Microsoft.EntityFrameworkCore;
// using Microsoft.AspNetCore.Authorization;

namespace FurnitureShopProjectRazil.Areas.Admin.Controllers
{
    [Area("Admin")]
    // [Authorize(Roles = "Admin")]
    public class ServiceController : Controller // Controller adını ServicesController etmək daha uyğun ola bilər
    {
        private readonly AppDbContext _context;

        public ServiceController(AppDbContext context)
        {
            _context = context;
        }

        // INDEX
        public async Task<IActionResult> Index()
        {
            var services = await _context.Services.OrderByDescending(s => s.Id).ToListAsync();
            return View(services);
        }

        // CREATE - GET
        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }

        // CREATE - POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Models.Services service)
        {
            if (ModelState.IsValid)
            {
                await _context.Services.AddAsync(service);
                await _context.SaveChangesAsync();
                TempData["SuccessMessage"] = "Xidmət uğurla yaradıldı.";
                return RedirectToAction(nameof(Index));
            }
            return View(service);
        }

        // UPDATE - GET
        [HttpGet]
        public async Task<IActionResult> Update(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var service = await _context.Services.FindAsync(id);
            if (service == null)
            {
                return NotFound();
            }
            return View(service);
        }

        // UPDATE - POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Update(int id, Models.Services service)
        {
            if (id != service.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(service);
                    await _context.SaveChangesAsync();
                    TempData["SuccessMessage"] = "Xidmət uğurla yeniləndi.";
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!ServiceExists(service.Id))
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
            return View(service);
        }

        // DELETE - GET
        [HttpGet]
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var service = await _context.Services.FirstOrDefaultAsync(m => m.Id == id);
            if (service == null)
            {
                return NotFound();
            }

            return View(service);
        }

        // DELETE - POST
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var service = await _context.Services.FindAsync(id);
            if (service == null)
            {
                TempData["ErrorMessage"] = "Xidmət tapılmadı.";
                return RedirectToAction(nameof(Index));
            }
            _context.Services.Remove(service);
            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = "Xidmət uğurla silindi.";
            return RedirectToAction(nameof(Index));
        }

        private bool ServiceExists(int id)
        {
            return _context.Services.Any(e => e.Id == id);
        }
    }
}