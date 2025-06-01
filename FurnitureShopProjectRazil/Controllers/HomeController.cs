// Controllers/HomeController.cs
using FurnitureShopProjectRazil.Data; // ApplicationDbContext üçün
using FurnitureShopProjectRazil.Models; // Home modeli üçün
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore; // Entity Framework Core metodları üçün (FirstOrDefaultAsync, ToListAsync etc.)
using System.Diagnostics; // ErrorViewModel üçün
using System.Linq; // OrderByDescending üçün
using System.Threading.Tasks; // Asinxron metodlar üçün

namespace FurnitureShopProjectRazil.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly AppDbContext _context; // Verilənlər bazası konteksti

        public HomeController(ILogger<HomeController> logger, AppDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        public async Task<IActionResult> Index()
        {
           
            Home heroData = await _context.Homes
                                      .OrderByDescending(h => h.Id) // Ən son əlavə edilənə görə sırala
                                      .FirstOrDefaultAsync(); // İlkini (yəni ən sonuncunu) götür

            // heroData null ola bilər, View bunu nəzərə almalıdır.
            return View(heroData);
        }

        
    }
}