// Controllers/ServicesController.cs
using FurnitureShopProjectRazil.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks; // Asinxron metodlar üçün
using System.Linq; // ToListAsync üçün

namespace FurnitureShopProjectRazil.Controllers
{
    public class ServicesController : Controller
    {
        private readonly AppDbContext _context;
        private readonly ILogger<ServicesController> _logger;


        public ServicesController(AppDbContext context, ILogger<ServicesController> logger)
        {
            _context = context;
            _logger = logger;
        }

        // GET: Services
        public async Task<IActionResult> Index()
        {
            var servicesList = await _context.Services.ToListAsync();
            return View(servicesList);
        }
    }
}